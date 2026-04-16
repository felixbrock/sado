"""
Benchmark pipeline: run a dataset against a list of LLMs and capture results.

Reusable across benchmarks. Each benchmark lives in `bench/<name>/` and
provides:
  - `dataset.jsonl`        — one entry per line (fields depend on the benchmark)
  - `prompt.py`            — exports SYSTEM_PROMPT, render_user_message(entry),
                             and parse_response(raw) -> (verdict, reason)

Each model lives in `bench/models/<id>.py` and subclasses `Model`. The
registry is in `bench/models/__init__.py`.

Usage:
    python bench/pipeline.py --benchmark adversarial_resistance --models opus-4-6
    python bench/pipeline.py --benchmark adversarial_resistance --models all
    python bench/pipeline.py --benchmark adversarial_resistance --models opus-4-6 --limit 20

Results are written to:
    bench/results/<benchmark>/<model>-<timestamp>.jsonl   # per-entry
    bench/results/<benchmark>/<model>-<timestamp>.json    # summary
    bench/results/<benchmark>/leaderboard-<timestamp>.json  # all-model summary
"""

import argparse
import asyncio
import importlib.util
import json
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from bench import models as model_registry  # noqa: E402


BENCH_ROOT = Path(__file__).parent
RESULTS_ROOT = BENCH_ROOT / "results"


@dataclass
class Benchmark:
    name: str
    dataset: list[dict]
    system_prompt: str
    render_user: Any
    parse_response: Any


def load_benchmark(name: str) -> Benchmark:
    bench_dir = BENCH_ROOT / name
    if not bench_dir.is_dir():
        raise FileNotFoundError(f"No benchmark directory at {bench_dir}")

    prompt_path = bench_dir / "prompt.py"
    dataset_path = bench_dir / "dataset.jsonl"
    if not prompt_path.exists():
        raise FileNotFoundError(f"Missing {prompt_path}")
    if not dataset_path.exists():
        raise FileNotFoundError(f"Missing {dataset_path}")

    spec = importlib.util.spec_from_file_location(f"bench_{name}_prompt", prompt_path)
    assert spec is not None and spec.loader is not None
    module: ModuleType = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    for attr in ("SYSTEM_PROMPT", "render_user_message", "parse_response"):
        if not hasattr(module, attr):
            raise AttributeError(f"{prompt_path} must export {attr}")

    dataset = [json.loads(l) for l in dataset_path.read_text().splitlines() if l.strip()]

    return Benchmark(
        name=name,
        dataset=dataset,
        system_prompt=module.SYSTEM_PROMPT,
        render_user=module.render_user_message,
        parse_response=module.parse_response,
    )


@dataclass
class EntryResult:
    id: str
    expected: str
    actual: str
    reason: str
    category: str
    difficulty: str
    source: str
    latency_ms: int
    error: str = ""


async def run_entry(
    model: model_registry.Model,
    benchmark: Benchmark,
    entry: dict,
    sem: asyncio.Semaphore,
) -> EntryResult:
    user = benchmark.render_user(entry)
    start = time.monotonic()
    try:
        async with sem:
            raw = await model.complete(benchmark.system_prompt, user)
        verdict, reason = benchmark.parse_response(raw)
        error = ""
    except Exception as exc:  # noqa: BLE001 — fail-closed and record the error
        verdict, reason, error = "DENY", f"(model error) {exc}", str(exc)
    latency_ms = int((time.monotonic() - start) * 1000)

    return EntryResult(
        id=entry["id"],
        expected=entry.get("expected_verdict", ""),
        actual=verdict,
        reason=reason,
        category=entry.get("category", ""),
        difficulty=entry.get("difficulty", ""),
        source=entry.get("source", ""),
        latency_ms=latency_ms,
        error=error,
    )


def summarize(model_name: str, results: list[EntryResult]) -> dict:
    total = len(results)
    correct = sum(1 for r in results if r.actual == r.expected)
    fn = [r for r in results if r.expected == "DENY" and r.actual != "DENY"]
    fp = [r for r in results if r.expected == "ALLOW" and r.actual != "ALLOW"]
    errors = sum(1 for r in results if r.error)

    per_cat: dict[str, dict[str, int]] = {}
    for r in results:
        c = per_cat.setdefault(r.category, {"total": 0, "correct": 0, "fn": 0, "fp": 0})
        c["total"] += 1
        if r.actual == r.expected:
            c["correct"] += 1
        if r.expected == "DENY" and r.actual != "DENY":
            c["fn"] += 1
        if r.expected == "ALLOW" and r.actual != "ALLOW":
            c["fp"] += 1

    avg_latency = sum(r.latency_ms for r in results) / total if total else 0

    return {
        "model": model_name,
        "total": total,
        "correct": correct,
        "accuracy": correct / total if total else 0.0,
        "false_negatives": len(fn),
        "false_positives": len(fp),
        "errors": errors,
        "avg_latency_ms": round(avg_latency, 1),
        "per_category": per_cat,
    }


def print_summary(summary: dict) -> None:
    print(f"\n── {summary['model']} ──")
    print(f"  total:       {summary['total']}")
    print(f"  correct:     {summary['correct']} ({summary['accuracy']*100:.1f}%)")
    print(f"  FN:          {summary['false_negatives']}  ← must be 0")
    print(f"  FP:          {summary['false_positives']}")
    if summary["errors"]:
        print(f"  errors:      {summary['errors']}")
    print(f"  avg latency: {summary['avg_latency_ms']} ms")
    if summary["per_category"]:
        print("  per category:")
        for cat, stats in sorted(summary["per_category"].items()):
            print(
                f"    {cat:<28} {stats['correct']}/{stats['total']}"
                f"  FN={stats['fn']}  FP={stats['fp']}"
            )


async def run_model(
    model: model_registry.Model,
    benchmark: Benchmark,
    entries: list[dict],
    out_dir: Path,
    timestamp: str,
) -> dict:
    sem = asyncio.Semaphore(model.max_concurrency)
    print(f"\n→ running {model.name} on {len(entries)} entries "
          f"(concurrency={model.max_concurrency}) ...")
    tasks = [run_entry(model, benchmark, e, sem) for e in entries]
    results = await asyncio.gather(*tasks)

    entries_path = out_dir / f"{model.name}-{timestamp}.jsonl"
    entries_path.write_text("\n".join(json.dumps(asdict(r)) for r in results) + "\n")

    summary = summarize(model.name, list(results))
    summary_path = out_dir / f"{model.name}-{timestamp}.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    print_summary(summary)
    print(f"  results → {entries_path}")
    return summary


async def main_async(args: argparse.Namespace) -> None:
    benchmark = load_benchmark(args.benchmark)
    entries = benchmark.dataset
    if args.limit:
        entries = entries[: args.limit]
    print(f"Benchmark: {benchmark.name}  ({len(entries)} entries)")

    if args.models == ["all"]:
        names = sorted(model_registry.REGISTRY)
        skipped = list(model_registry.UNIMPLEMENTED)
        if skipped:
            print(f"Skipping unimplemented models: {', '.join(skipped)}")
    else:
        names = args.models

    out_dir = RESULTS_ROOT / benchmark.name
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    leaderboard: list[dict] = []
    for name in names:
        model = model_registry.load(name)
        summary = await run_model(model, benchmark, entries, out_dir, timestamp)
        leaderboard.append(summary)

    leaderboard_path = out_dir / f"leaderboard-{timestamp}.json"
    leaderboard_path.write_text(json.dumps(leaderboard, indent=2))
    print(f"\nLeaderboard → {leaderboard_path}")
    print_leaderboard(leaderboard)


def print_leaderboard(leaderboard: list[dict]) -> None:
    if not leaderboard:
        return
    print("\n── leaderboard ──")
    print(f"{'model':<20} {'acc':>7} {'FN':>5} {'FP':>5} {'err':>5} {'latency':>9}")
    for s in sorted(leaderboard, key=lambda x: (-x["accuracy"], x["false_negatives"])):
        print(
            f"{s['model']:<20} "
            f"{s['accuracy']*100:>6.1f}% "
            f"{s['false_negatives']:>5} "
            f"{s['false_positives']:>5} "
            f"{s['errors']:>5} "
            f"{s['avg_latency_ms']:>7.0f}ms"
        )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="LLM benchmark pipeline")
    p.add_argument("--benchmark", required=True, help="Benchmark directory name under bench/")
    p.add_argument(
        "--models",
        nargs="+",
        required=True,
        help=(
            "Space-separated model ids, or 'all' for every registered model. "
            f"Registered: {', '.join(sorted(model_registry.REGISTRY)) or '(none)'}"
        ),
    )
    p.add_argument("--limit", type=int, default=0, help="Run only the first N entries (0 = all)")
    return p.parse_args()


if __name__ == "__main__":
    asyncio.run(main_async(parse_args()))
