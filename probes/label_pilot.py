"""
Label a 50-row pilot from `probes/dataset.jsonl` with Opus 4.6.

This is the fail-fast gate before paying to label the full ~3K dataset.
Sample is stratified 25 ALLOW-candidate / 25 DENY-candidate so the review
sees labels on both sides of the intended class boundary. The prompt
deliberately reuses `bench/adversarial_resistance/prompt.py` so the train
inputs and the bench eval inputs share formatting — the probe's learned
features only transfer if the activation distributions match.

Output: `probes/pilot_labeled.jsonl` — a throwaway file. The canonical
source (`probes/dataset.jsonl`) stays unlabeled.

Usage:
    uv run python probes/label_pilot.py [--n 50] [--seed 20260417]
"""

import argparse
import asyncio
import json
import os
import random
import sys
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bench.adversarial_resistance.prompt import (  # noqa: E402
    SYSTEM_PROMPT,
    parse_response,
    render_user_message,
)
from bench.models.anthropic import AnthropicModel  # noqa: E402

DATASET_PATH = Path(__file__).parent / "dataset.jsonl"
OUT_PATH = Path(__file__).parent / "pilot_labeled.jsonl"


def load_dataset(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.strip():
                rows.append(json.loads(line))
    return rows


def stratified_sample(rows: list[dict], n: int, rng: random.Random) -> list[dict]:
    allow = [r for r in rows if r["intended_class"] == "allow_candidate"]
    deny = [r for r in rows if r["intended_class"] == "deny_candidate"]
    half = n // 2
    rng.shuffle(allow)
    rng.shuffle(deny)
    sample = allow[:half] + deny[:n - half]
    rng.shuffle(sample)
    return sample


async def label_one(model: AnthropicModel, row: dict) -> dict:
    user = render_user_message(row)
    try:
        raw = await model.complete(SYSTEM_PROMPT, user)
        verdict, reason = parse_response(raw)
    except Exception as e:
        return {**row, "verdict": "API_ERROR", "reason": f"{type(e).__name__}: {e}"}
    return {**row, "verdict": verdict, "reason": reason}


async def main_async(args: argparse.Namespace) -> None:
    rows = load_dataset(DATASET_PATH)
    rng = random.Random(args.seed)
    pilot = stratified_sample(rows, args.n, rng)

    model = AnthropicModel("claude-opus-4-6", "claude-opus-4-6")

    print(f"Labeling {len(pilot)} pilot rows with Opus 4.6 ...", flush=True)
    results = await asyncio.gather(*(label_one(model, r) for r in pilot))

    OUT_PATH.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in results) + "\n"
    )

    agree = sum(
        1 for r in results
        if (r["intended_class"] == "allow_candidate" and r["verdict"] == "ALLOW")
        or (r["intended_class"] == "deny_candidate" and r["verdict"] == "DENY")
    )
    parse_errors = sum(1 for r in results if r["verdict"] == "PARSE_ERROR")
    api_errors = sum(1 for r in results if r["verdict"] == "API_ERROR")

    print(f"\nWrote {len(results)} labeled rows to {OUT_PATH}", flush=True)
    print(f"  intended-class agreement: {agree}/{len(results)}", flush=True)
    print(f"  parse errors            : {parse_errors}", flush=True)
    print(f"  api errors              : {api_errors}", flush=True)
    print("\nAgreement is a sanity signal, not ground truth —", flush=True)
    print("the user review is what decides if labeling is ready to scale.", flush=True)


def main() -> None:
    load_dotenv(ROOT / "bench" / ".env")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("ANTHROPIC_API_KEY is not set; aborting.")

    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=50)
    p.add_argument("--seed", type=int, default=20260417)
    args = p.parse_args()

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
