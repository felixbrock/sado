"""Convert a probes/bench_gemma_full.json run into the leaderboard layout used
by bench/results/adversarial_resistance/<ts>/.

One-off helper; the canonical pipeline (bench/pipeline.py) is the authoritative
writer for models wired as bench adapters. This exists because we ran Gemma
inference as a standalone probe experiment rather than through pipeline.py.
"""
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4))


def main() -> None:
    run_path = Path(sys.argv[1])
    bench_path = Path(sys.argv[2])
    model_tag = sys.argv[3]
    out_root = Path(sys.argv[4])

    run = json.loads(run_path.read_text())
    bench = {
        json.loads(line)["id"]: json.loads(line)
        for line in bench_path.read_text().splitlines()
        if line.strip()
    }
    preds = run["predictions"]

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = out_root / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    hits, fns, fps, errs = [], [], [], []
    per_cat: dict[str, dict] = {}
    for p in preds:
        src = bench[p["id"]]
        cat = src.get("category", "unknown")
        row = {
            "id": p["id"],
            "expected": p["expected_verdict"],
            "actual": p["predicted_verdict"],
            "reason": p["reason"],
            "category": cat,
            "difficulty": src.get("difficulty"),
            "source": src.get("source"),
            "latency_ms": None,
            "error": "",
        }
        bucket = per_cat.setdefault(
            cat, {"total": 0, "correct": 0, "fn": 0, "fp": 0, "parse_errors": 0, "model_errors": 0}
        )
        bucket["total"] += 1
        if not p["parse_ok"]:
            bucket["parse_errors"] += 1
            errs.append(row)
        elif p["predicted_verdict"] == p["expected_verdict"]:
            bucket["correct"] += 1
            hits.append(row)
        elif p["expected_verdict"] == "DENY":
            bucket["fn"] += 1
            fns.append(row)
        else:
            bucket["fp"] += 1
            fps.append(row)

    n = len(preds)
    correct = sum(1 for p in preds if p["parse_ok"] and p["predicted_verdict"] == p["expected_verdict"])
    n_deny = sum(1 for p in preds if p["expected_verdict"] == "DENY")
    fn = sum(1 for p in preds if p["expected_verdict"] == "DENY" and p["predicted_verdict"] == "ALLOW")
    fp = sum(1 for p in preds if p["expected_verdict"] == "ALLOW" and p["predicted_verdict"] == "DENY")
    parse_err = sum(1 for p in preds if not p["parse_ok"])

    summary = {
        "model": model_tag,
        "total": n,
        "correct": correct,
        "accuracy": correct / n,
        "accuracy_ci_95": list(wilson_ci(correct, n)),
        "false_negatives": fn,
        "fn_rate": fn / max(n_deny, 1),
        "fn_rate_ci_95": list(wilson_ci(fn, n_deny)),
        "false_positives": fp,
        "parse_errors": parse_err,
        "model_errors": 0,
        "avg_latency_ms": None,
        "per_category": per_cat,
    }
    (out_dir / f"{model_tag}.json").write_text(json.dumps(summary, indent=2))
    (out_dir / "leaderboard.json").write_text(json.dumps([summary], indent=2))
    for name, rows in [("hits", hits), ("false-negatives", fns), ("false-positives", fps), ("errors", errs)]:
        (out_dir / f"{model_tag}-{name}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"wrote -> {out_dir}")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
