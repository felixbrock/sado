"""
Label the full `probes/dataset.jsonl` with Opus 4.6.

Runs after the pilot review (`probes/pilot_labeled.jsonl`) has been
accepted. Reuses `bench/adversarial_resistance/prompt.py` so the training
inputs share formatting with the bench eval. Writes to
`probes/dataset_labeled.jsonl`; the canonical source stays unlabeled.

Resumable: if the output file exists, rows whose `id` is already labeled
are skipped. Safe to re-run after interruption.

Usage:
    uv run python probes/label_full.py [--concurrency 10]
"""

import argparse
import asyncio
import json
import os
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
OUT_PATH = Path(__file__).parent / "dataset_labeled.jsonl"


def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.strip():
                yield json.loads(line)


def load_done_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {r["id"] for r in _iter_jsonl(path)}


async def label_one(
    model: AnthropicModel,
    row: dict,
    sem: asyncio.Semaphore,
) -> dict:
    async with sem:
        user = render_user_message(row)
        try:
            raw = await model.complete(SYSTEM_PROMPT, user)
            verdict, reason = parse_response(raw)
        except Exception as e:
            return {**row, "verdict": "API_ERROR", "reason": f"{type(e).__name__}: {e}"}
        return {**row, "verdict": verdict, "reason": reason}


async def main_async(args: argparse.Namespace) -> None:
    all_rows = list(_iter_jsonl(DATASET_PATH))
    done = load_done_ids(OUT_PATH)
    todo = [r for r in all_rows if r["id"] not in done]

    print(f"Total rows: {len(all_rows)}  already labeled: {len(done)}  to do: {len(todo)}", flush=True)
    if not todo:
        print("Nothing to do.", flush=True)
        return

    model = AnthropicModel("claude-opus-4-6", "claude-opus-4-6")
    sem = asyncio.Semaphore(args.concurrency)

    # Append as each row finishes so we can resume after an interruption.
    out_fh = OUT_PATH.open("a", encoding="utf-8")
    write_lock = asyncio.Lock()
    counts = {"done": 0, "allow": 0, "deny": 0, "parse_error": 0, "api_error": 0}

    async def _run(row: dict) -> None:
        labeled = await label_one(model, row, sem)
        async with write_lock:
            out_fh.write(json.dumps(labeled, ensure_ascii=False) + "\n")
            out_fh.flush()
            counts["done"] += 1
            v = labeled["verdict"]
            if v == "ALLOW":
                counts["allow"] += 1
            elif v == "DENY":
                counts["deny"] += 1
            elif v == "PARSE_ERROR":
                counts["parse_error"] += 1
            elif v == "API_ERROR":
                counts["api_error"] += 1
            if counts["done"] % 100 == 0 or counts["done"] == len(todo):
                print(
                    f"  progress: {counts['done']}/{len(todo)}  "
                    f"ALLOW={counts['allow']} DENY={counts['deny']} "
                    f"parse_err={counts['parse_error']} api_err={counts['api_error']}",
                    flush=True,
                )

    try:
        await asyncio.gather(*(_run(r) for r in todo))
    finally:
        out_fh.close()

    print(f"\nWrote labels to {OUT_PATH}", flush=True)
    print(f"  ALLOW      : {counts['allow']}", flush=True)
    print(f"  DENY       : {counts['deny']}", flush=True)
    print(f"  parse_error: {counts['parse_error']}", flush=True)
    print(f"  api_error  : {counts['api_error']}", flush=True)


def main() -> None:
    load_dotenv(ROOT / "bench" / ".env")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("ANTHROPIC_API_KEY is not set; aborting.")

    p = argparse.ArgumentParser()
    p.add_argument("--concurrency", type=int, default=10,
                   help="Max concurrent Anthropic requests.")
    args = p.parse_args()

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
