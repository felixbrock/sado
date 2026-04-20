"""
Extract mean-pooled hidden states from google/gemma-4-E2B-it for the linear probe.

Reads:
  - probes/dataset_labeled.jsonl            (train+val source)
  - bench/adversarial_resistance/dataset.jsonl   (held-out test)

Writes (one per split):
  - <out>/train.pt, <out>/val.pt, <out>/test.pt
Each holds {ids, labels, hidden_mid, hidden_last, meta}.

Run on the pod after model download. Stratified 80/20 split on verdict,
seed=42. Pooling is attention-masked mean over the sequence dim.
"""
import argparse
import json
import random
import sys
import time
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "bench" / "adversarial_resistance"))
from prompt import SYSTEM_PROMPT, render_user_message  # noqa: E402

MODEL_DIR = "/workspace/models/gemma-4-E2B-it"
REVISION = "b4a601102c3d45e2b7b50e2057a6d5ec8ed4adcf"
MIDDLE_LAYER = 18
LAST_LAYER = 35
DEVICE = "cuda:0"
MAX_TOKENS = 8192


def build_prompt(entry: dict) -> str:
    return f"{SYSTEM_PROMPT}\n\n{render_user_message(entry)}"


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def stratified_split(rows: list[dict], seed: int, val_frac: float) -> tuple[list[dict], list[dict]]:
    allow = [r for r in rows if r["verdict"] == "ALLOW"]
    deny = [r for r in rows if r["verdict"] == "DENY"]
    rng = random.Random(seed)
    rng.shuffle(allow)
    rng.shuffle(deny)
    n_a = int(round(len(allow) * val_frac))
    n_d = int(round(len(deny) * val_frac))
    val = allow[:n_a] + deny[:n_d]
    train = allow[n_a:] + deny[n_d:]
    rng.shuffle(val)
    rng.shuffle(train)
    return train, val


@torch.inference_mode()
def extract_one(model, tok, text: str) -> tuple[torch.Tensor, torch.Tensor]:
    inputs = tok(text, return_tensors="pt", truncation=True, max_length=MAX_TOKENS).to(DEVICE)
    out = model(**inputs, output_hidden_states=True, use_cache=False)
    mask = inputs["attention_mask"].unsqueeze(-1).float()

    def pool(h: torch.Tensor) -> torch.Tensor:
        return (h.float() * mask).sum(dim=1) / mask.sum(dim=1)

    mid = pool(out.hidden_states[MIDDLE_LAYER]).squeeze(0).to(torch.bfloat16).cpu()
    last = pool(out.hidden_states[LAST_LAYER]).squeeze(0).to(torch.bfloat16).cpu()
    return mid, last


def label_for(verdict: str) -> int:
    return 0 if verdict == "ALLOW" else 1


def extract_split(model, tok, rows: list[dict], label_key: str) -> dict:
    ids, labels, mid_list, last_list = [], [], [], []
    t0 = time.perf_counter()
    for i, r in enumerate(rows):
        mid, last = extract_one(model, tok, build_prompt(r))
        ids.append(r["id"])
        labels.append(label_for(r[label_key]))
        mid_list.append(mid)
        last_list.append(last)
        if (i + 1) % 100 == 0:
            rate = (i + 1) / (time.perf_counter() - t0)
            eta_m = (len(rows) - i - 1) / rate / 60
            print(f"  {i+1}/{len(rows)}  {rate:.2f} prompts/s  eta {eta_m:.1f}m", flush=True)
    return {
        "ids": ids,
        "labels": torch.tensor(labels, dtype=torch.int8),
        "hidden_mid": torch.stack(mid_list),
        "hidden_last": torch.stack(last_list),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-data", required=True)
    ap.add_argument("--test-data", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--val-frac", type=float, default=0.2)
    ap.add_argument("--limit", type=int, default=None, help="debug: cap rows per split")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    src = load_jsonl(Path(args.train_data))
    test_rows = load_jsonl(Path(args.test_data))
    train_rows, val_rows = stratified_split(src, args.seed, args.val_frac)

    if args.limit:
        train_rows = train_rows[: args.limit]
        val_rows = val_rows[: args.limit]
        test_rows = test_rows[: args.limit]

    n_t_allow = sum(1 for r in train_rows if r["verdict"] == "ALLOW")
    n_v_allow = sum(1 for r in val_rows if r["verdict"] == "ALLOW")
    print(f"train={len(train_rows)} (ALLOW={n_t_allow})  val={len(val_rows)} (ALLOW={n_v_allow})  test={len(test_rows)}")

    print("loading model...")
    t0 = time.perf_counter()
    tok = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForCausalLM.from_pretrained(MODEL_DIR, dtype=torch.bfloat16, device_map=DEVICE)
    model.eval()
    print(f"loaded in {time.perf_counter()-t0:.1f}s")

    import transformers
    meta = {
        "model_revision": REVISION,
        "middle_layer": MIDDLE_LAYER,
        "last_layer": LAST_LAYER,
        "pooling": "mean_masked_bf16",
        "transformers_version": transformers.__version__,
        "torch_version": torch.__version__,
        "split_seed": args.seed,
        "val_frac": args.val_frac,
    }

    for name, rows, label_key in [
        ("train", train_rows, "verdict"),
        ("val", val_rows, "verdict"),
        ("test", test_rows, "expected_verdict"),
    ]:
        print(f"=== extracting {name} ({len(rows)} rows) ===")
        data = extract_split(model, tok, rows, label_key)
        data["meta"] = {**meta, "split": name, "n_rows": len(rows)}
        out_path = out_dir / f"{name}.pt"
        torch.save(data, out_path)
        print(f"  saved -> {out_path}  hidden_mid {tuple(data['hidden_mid'].shape)}")


if __name__ == "__main__":
    main()
