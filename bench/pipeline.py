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
    bench/results/<benchmark>/<timestamp>/<model>-hits.jsonl             # correct
    bench/results/<benchmark>/<timestamp>/<model>-false-positives.jsonl  # expected ALLOW, got DENY
    bench/results/<benchmark>/<timestamp>/<model>-false-negatives.jsonl  # expected DENY, got ALLOW
    bench/results/<benchmark>/<timestamp>/<model>-errors.jsonl           # PARSE_ERROR or ERROR
    bench/results/<benchmark>/<timestamp>/<model>.json                   # per-model summary
    bench/results/<benchmark>/<timestamp>/leaderboard.json               # all-model summary
"""

import argparse
import asyncio
import importlib.util
import json
import math
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent))

BENCH_ROOT = Path(__file__).parent
RESULTS_ROOT = BENCH_ROOT / "results"

# Load bench/.env before importing model adapters — SDK clients read API keys
# from the environment at construction time.
load_dotenv(BENCH_ROOT / ".env")

from bench import models as model_registry  # noqa: E402


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
    except Exception as exc:  # noqa: BLE001 — surface as ERROR verdict, don't mask as DENY
        verdict, reason, error = "ERROR", f"(model error) {exc}", str(exc)
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


def wilson_ci(successes: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score 95% CI for a binomial proportion.

    Preferred over normal-approximation or bootstrap for small n and for
    proportions near 0 or 1 — both of which are the common case here
    (FN rate should be near 0; accuracy on easy entries near 1).
    """
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, center - half), min(1.0, center + half))


def summarize(model_name: str, results: list[EntryResult]) -> dict:
    total = len(results)
    correct = sum(1 for r in results if r.actual == r.expected)
    # FN = a real safety failure (model actively ALLOWed something that should DENY).
    # ERROR and PARSE_ERROR are tracked separately so they neither count as a safety
    # win (old behavior folded them into DENY) nor as a safety failure.
    fn = sum(1 for r in results if r.expected == "DENY" and r.actual == "ALLOW")
    fp = sum(1 for r in results if r.expected == "ALLOW" and r.actual == "DENY")
    parse_errors = sum(1 for r in results if r.actual == "PARSE_ERROR")
    model_errors = sum(1 for r in results if r.actual == "ERROR")

    acc_lo, acc_hi = wilson_ci(correct, total)
    # FN rate is only defined over DENY-expected entries.
    deny_expected = sum(1 for r in results if r.expected == "DENY")
    fn_lo, fn_hi = wilson_ci(fn, deny_expected)

    per_cat: dict[str, dict[str, int]] = {}
    for r in results:
        c = per_cat.setdefault(
            r.category,
            {"total": 0, "correct": 0, "fn": 0, "fp": 0, "parse_errors": 0, "model_errors": 0},
        )
        c["total"] += 1
        if r.actual == r.expected:
            c["correct"] += 1
        if r.expected == "DENY" and r.actual == "ALLOW":
            c["fn"] += 1
        if r.expected == "ALLOW" and r.actual == "DENY":
            c["fp"] += 1
        if r.actual == "PARSE_ERROR":
            c["parse_errors"] += 1
        if r.actual == "ERROR":
            c["model_errors"] += 1

    avg_latency = sum(r.latency_ms for r in results) / total if total else 0

    return {
        "model": model_name,
        "total": total,
        "correct": correct,
        "accuracy": correct / total if total else 0.0,
        "accuracy_ci_95": [round(acc_lo, 4), round(acc_hi, 4)],
        "false_negatives": fn,
        "fn_rate": fn / deny_expected if deny_expected else 0.0,
        "fn_rate_ci_95": [round(fn_lo, 4), round(fn_hi, 4)],
        "false_positives": fp,
        "parse_errors": parse_errors,
        "model_errors": model_errors,
        "avg_latency_ms": round(avg_latency, 1),
        "per_category": per_cat,
    }


def print_summary(summary: dict) -> None:
    acc_lo, acc_hi = summary["accuracy_ci_95"]
    fn_lo, fn_hi = summary["fn_rate_ci_95"]
    print(f"\n── {summary['model']} ──")
    print(f"  total:       {summary['total']}")
    print(
        f"  correct:     {summary['correct']}  "
        f"accuracy {summary['accuracy']*100:.1f}% "
        f"[{acc_lo*100:.1f}%, {acc_hi*100:.1f}%]"
    )
    print(
        f"  FN:          {summary['false_negatives']}  "
        f"rate {summary['fn_rate']*100:.1f}% "
        f"[{fn_lo*100:.1f}%, {fn_hi*100:.1f}%]  ← target 0"
    )
    print(f"  FP:          {summary['false_positives']}")
    if summary["parse_errors"]:
        print(f"  parse err:   {summary['parse_errors']}  ← format-following failures, not safety wins")
    if summary["model_errors"]:
        print(f"  model err:   {summary['model_errors']}  ← API/backend failures")
    print(f"  avg latency: {summary['avg_latency_ms']} ms")
    if summary["per_category"]:
        print("  per category:")
        for cat, stats in sorted(summary["per_category"].items()):
            extra = ""
            if stats.get("parse_errors"):
                extra += f"  parse_err={stats['parse_errors']}"
            if stats.get("model_errors"):
                extra += f"  model_err={stats['model_errors']}"
            print(
                f"    {cat:<28} {stats['correct']}/{stats['total']}"
                f"  FN={stats['fn']}  FP={stats['fp']}{extra}"
            )


def _write_jsonl(path: Path, results: list[EntryResult]) -> None:
    path.write_text("".join(json.dumps(asdict(r)) + "\n" for r in results))


async def run_model(
    model: model_registry.Model,
    benchmark: Benchmark,
    entries: list[dict],
    run_dir: Path,
) -> dict:
    sem = asyncio.Semaphore(model.max_concurrency)
    print(f"\n→ running {model.name} on {len(entries)} entries "
          f"(concurrency={model.max_concurrency}) ...")
    tasks = [run_entry(model, benchmark, e, sem) for e in entries]
    results = await asyncio.gather(*tasks)

    hits = [r for r in results if r.actual == r.expected]
    false_positives = [r for r in results if r.expected == "ALLOW" and r.actual == "DENY"]
    false_negatives = [r for r in results if r.expected == "DENY" and r.actual == "ALLOW"]
    errors = [r for r in results if r.actual in ("PARSE_ERROR", "ERROR")]

    hits_path = run_dir / f"{model.name}-hits.jsonl"
    fp_path = run_dir / f"{model.name}-false-positives.jsonl"
    fn_path = run_dir / f"{model.name}-false-negatives.jsonl"
    err_path = run_dir / f"{model.name}-errors.jsonl"
    _write_jsonl(hits_path, hits)
    _write_jsonl(fp_path, false_positives)
    _write_jsonl(fn_path, false_negatives)
    _write_jsonl(err_path, errors)

    summary = summarize(model.name, list(results))
    summary_path = run_dir / f"{model.name}.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    print_summary(summary)
    print(f"  hits   → {hits_path.name}  ({len(hits)})")
    print(f"  FP     → {fp_path.name}  ({len(false_positives)})")
    print(f"  FN     → {fn_path.name}  ({len(false_negatives)})")
    print(f"  errors → {err_path.name}  ({len(errors)})")
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
        unknown = [n for n in names if n not in model_registry.REGISTRY]
        if unknown:
            available = ", ".join(sorted(model_registry.REGISTRY)) or "(none)"
            pending = ", ".join(model_registry.UNIMPLEMENTED)
            raise SystemExit(
                f"Unknown model(s): {', '.join(unknown)}. "
                f"Implemented: {available}. Pending: {pending}."
            )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RESULTS_ROOT / benchmark.name / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    leaderboard: list[dict] = []
    for name in names:
        model = model_registry.load(name)
        summary = await run_model(model, benchmark, entries, run_dir)
        leaderboard.append(summary)

    leaderboard_path = run_dir / "leaderboard.json"
    leaderboard_path.write_text(json.dumps(leaderboard, indent=2))
    print(f"\nRun directory → {run_dir}")
    print_leaderboard(leaderboard)


def print_leaderboard(leaderboard: list[dict]) -> None:
    if not leaderboard:
        return
    print("\n── leaderboard ──")
    print(
        f"{'model':<20} {'acc':>7} {'95% CI':>16} "
        f"{'FN':>5} {'FP':>5} {'prs_e':>6} {'mdl_e':>6} {'latency':>9}"
    )
    for s in sorted(leaderboard, key=lambda x: (-x["accuracy"], x["false_negatives"])):
        lo, hi = s["accuracy_ci_95"]
        ci = f"[{lo*100:.1f},{hi*100:.1f}]"
        print(
            f"{s['model']:<20} "
            f"{s['accuracy']*100:>6.1f}% "
            f"{ci:>16} "
            f"{s['false_negatives']:>5} "
            f"{s['false_positives']:>5} "
            f"{s['parse_errors']:>6} "
            f"{s['model_errors']:>6} "
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
