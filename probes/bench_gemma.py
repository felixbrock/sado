"""
Run Gemma-4-E2B-it as a judge against bench/adversarial_resistance/dataset.jsonl.

For each of the 200 bench rows: render the instruction-tuned chat prompt,
generate a short JSON verdict, parse via `prompt.parse_response`, and compute
accuracy + FN-rate + Wilson upper bound on DENY cases.

This is the head-to-head baseline for the linear probe trained on this
same model's activations.
"""
import argparse
import json
import math
import sys
import time
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "bench" / "adversarial_resistance"))
from prompt import SYSTEM_PROMPT, parse_response, render_user_message  # noqa: E402

MODEL_DIR = "/workspace/models/gemma-4-E2B-it"
REVISION = "b4a601102c3d45e2b7b50e2057a6d5ec8ed4adcf"
DEVICE = "cuda:0"
MAX_NEW = 128


def wilson_upper(k: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 1.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return centre + half


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def render_chat_text(tok, entry: dict) -> str:
    msgs = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": render_user_message(entry)},
    ]
    try:
        return tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False)
    except Exception:
        merged = [{"role": "user", "content": f"{SYSTEM_PROMPT}\n\n{render_user_message(entry)}"}]
        return tok.apply_chat_template(merged, add_generation_prompt=True, tokenize=False)


@torch.inference_mode()
def judge_one(model, tok, entry: dict) -> tuple[str, str, str]:
    text = render_chat_text(tok, entry)
    inputs = tok(text, return_tensors="pt").to(DEVICE)
    in_len = inputs["input_ids"].shape[1]
    out = model.generate(
        **inputs,
        max_new_tokens=MAX_NEW,
        do_sample=False,
        pad_token_id=tok.eos_token_id,
    )
    gen = out[0, in_len:]
    raw = tok.decode(gen, skip_special_tokens=True)
    verdict, reason = parse_response(raw)
    return verdict, reason, raw


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench-data", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    rows = load_jsonl(Path(args.bench_data))
    if args.limit:
        rows = rows[: args.limit]

    print("loading model...")
    t0 = time.perf_counter()
    tok = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForCausalLM.from_pretrained(MODEL_DIR, dtype=torch.bfloat16, device_map=DEVICE)
    model.eval()
    print(f"loaded in {time.perf_counter()-t0:.1f}s")

    preds = []
    t0 = time.perf_counter()
    for i, r in enumerate(rows):
        verdict, reason, raw = judge_one(model, tok, r)
        preds.append(
            {
                "id": r["id"],
                "expected_verdict": r["expected_verdict"],
                "predicted_verdict": verdict,
                "parse_ok": verdict in ("ALLOW", "DENY"),
                "reason": reason,
                "category": r.get("category"),
                "raw": raw,
            }
        )
        if (i + 1) % 20 == 0:
            rate = (i + 1) / (time.perf_counter() - t0)
            eta_m = (len(rows) - i - 1) / rate / 60
            print(f"  {i+1}/{len(rows)}  {rate:.2f}/s  eta {eta_m:.1f}m", flush=True)

    n = len(preds)
    n_deny = sum(1 for p in preds if p["expected_verdict"] == "DENY")
    fn = sum(1 for p in preds if p["expected_verdict"] == "DENY" and p["predicted_verdict"] == "ALLOW")
    parse_err = sum(1 for p in preds if not p["parse_ok"])
    correct = sum(1 for p in preds if p["parse_ok"] and p["predicted_verdict"] == p["expected_verdict"])

    summary = {
        "model_revision": REVISION,
        "n": n,
        "n_deny": n_deny,
        "correct": correct,
        "accuracy": correct / n,
        "fn": fn,
        "fn_rate": fn / max(n_deny, 1),
        "fn_wilson_ub": wilson_upper(fn, n_deny),
        "parse_errors": parse_err,
    }
    Path(args.out).write_text(json.dumps({"summary": summary, "predictions": preds}, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
