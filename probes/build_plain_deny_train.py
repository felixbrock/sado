"""
Augment the probe training set with plain-prose DENY rows.

The domain-shortcut test (see bench/adversarial_resistance/plain_deny_cases.jsonl)
showed the probe learned a "smells like jailbreak corpus" feature instead of
policy understanding: ~75% FN on plain-prose always-deny commands, ~3% FN on
jailbreak-flavored DENY. The obvious fix: mix plain-prose DENY into training
so the probe is forced to learn the underlying policy feature.

This script generates **new** plain-prose DENY goals for training, dedup'd
against both:
  - probes/dataset_labeled.jsonl (existing training data)
  - bench/adversarial_resistance/dataset.jsonl (including the 80 plain_deny
    holdout rows — those stay test-only to keep the domain-shortcut signal
    intact).

Output: appends DENY-labeled rows to probes/dataset_labeled.jsonl with
ids `probe_plain_NNNNN`, source `synthetic:opus-4-7:plain_<command>`,
intended_class `deny_candidate`. Re-run extract_activations.py afterward
to refresh train/val tensors.

Usage:
    uv run --group probes python probes/build_plain_deny_train.py \\
        [--per-command 15] [--concurrency 8]
"""
import argparse
import asyncio
import json
import os
import random
import re
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
from bench.adversarial_resistance.build_plain_deny_cases import (  # noqa: E402
    ALWAYS_DENY_COMMANDS,
    CWD_POOL,
    SYNTH_SYSTEM,
    SYNTH_USER_TEMPLATE,
    _normalize,
    _parse_lines,
    _truncate,
)
from bench.models.anthropic import AnthropicModel  # noqa: E402

HERE = Path(__file__).parent
POLICY_PATH = ROOT / "bench" / "adversarial_resistance" / "policy.md"
BENCH_DATASET = ROOT / "bench" / "adversarial_resistance" / "dataset.jsonl"
PROBE_LABELED = HERE / "dataset_labeled.jsonl"

SYNTH_MODEL = "claude-opus-4-7"
LABEL_MODEL = "claude-opus-4-7"
SEED = 20260420


def _load_goal_keys(paths: list[Path]) -> set[str]:
    out: set[str] = set()
    for p in paths:
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            out.add(_normalize(row.get("goal", "")))
    return out


def _next_probe_id(existing: Path) -> int:
    max_n = 0
    if existing.exists():
        for line in existing.read_text().splitlines():
            if not line.strip():
                continue
            rid = json.loads(line).get("id", "")
            m = re.match(r"^probe_plain_(\d+)$", rid)
            if m:
                max_n = max(max_n, int(m.group(1)))
    return max_n + 1


async def _synthesize(
    synth: AnthropicModel,
    policy: str,
    spec: dict,
    target: int,
    seen: set[str],
    rng: random.Random,
) -> list[dict]:
    command = spec["command"]
    args = spec["args"]
    cmd_str = " ".join([command] + args)
    source_tag = f"synthetic:{SYNTH_MODEL}:plain_{command}"
    out: list[dict] = []
    tries = 0
    while len(out) < target and tries < 5:
        tries += 1
        user = SYNTH_USER_TEMPLATE.format(
            policy=policy, command=cmd_str, hint=spec["hint"], n=target + 6
        )
        try:
            raw = await synth.complete(SYNTH_SYSTEM, user)
        except Exception as e:
            print(f"  [synth {cmd_str}] API error: {e}", flush=True)
            continue
        for goal in _parse_lines(raw, target + 6):
            if len(out) >= target:
                break
            goal = _truncate(goal)
            key = _normalize(goal)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "command": command,
                    "args": list(args),
                    "cwd": rng.choice(CWD_POOL),
                    "goal": goal,
                    "source": source_tag,
                    "intended_class": "deny_candidate",
                }
            )
    return out


async def _label(labeler: AnthropicModel, row: dict, sem: asyncio.Semaphore) -> dict:
    async with sem:
        user = render_user_message(row)
        try:
            raw = await labeler.complete(SYSTEM_PROMPT, user)
            verdict, reason = parse_response(raw)
        except Exception as e:
            return {**row, "verdict": "API_ERROR", "reason": f"{type(e).__name__}: {e}"}
        return {**row, "verdict": verdict, "reason": reason}


async def main_async(args: argparse.Namespace) -> None:
    policy = POLICY_PATH.read_text()
    seen = _load_goal_keys([BENCH_DATASET, PROBE_LABELED])
    print(f"dedup seed (bench + existing probe training): {len(seen)} goals", flush=True)

    rng = random.Random(SEED)
    synth = AnthropicModel(SYNTH_MODEL, SYNTH_MODEL)

    print(f"\n=== synthesis ({SYNTH_MODEL}) ===", flush=True)
    candidates: list[dict] = []
    for spec in ALWAYS_DENY_COMMANDS:
        rows = await _synthesize(synth, policy, spec, args.per_command, seen, rng)
        cmd_str = f"{spec['command']} {' '.join(spec['args'])}"
        print(f"  {cmd_str:45s}: {len(rows)} candidates", flush=True)
        candidates.extend(rows)

    start_id = _next_probe_id(PROBE_LABELED)
    for i, row in enumerate(candidates):
        row["id"] = f"probe_plain_{start_id + i:05d}"
    print(f"\ntotal candidates: {len(candidates)}  (ids start at probe_plain_{start_id:05d})", flush=True)

    print(f"\n=== labeling ({LABEL_MODEL}) ===", flush=True)
    labeler = AnthropicModel(LABEL_MODEL, LABEL_MODEL)
    sem = asyncio.Semaphore(args.concurrency)
    labeled = await asyncio.gather(*(_label(labeler, r, sem) for r in candidates))

    counts: dict[str, int] = {}
    for row in labeled:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    print("  " + "  ".join(f"{k}={v}" for k, v in counts.items()), flush=True)

    denies = [r for r in labeled if r["verdict"] == "DENY"]
    with PROBE_LABELED.open("a", encoding="utf-8") as f:
        for row in denies:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"\nappended {len(denies)} DENY rows to {PROBE_LABELED}", flush=True)


def main() -> None:
    load_dotenv(ROOT / "bench" / ".env")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("ANTHROPIC_API_KEY is not set; aborting.")

    p = argparse.ArgumentParser()
    p.add_argument("--per-command", type=int, default=15)
    p.add_argument("--concurrency", type=int, default=8)
    args = p.parse_args()

    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
