[gemma-4-e2b]: https://huggingface.co/google/gemma-4-E2B

# Models

[top-local-models-list]: https://www.latent.space/p/ainews-top-local-models-list-april?publication_id=1084089&post_id=194162215&isFreemail=true&r=1qz21d&triedRedirect=true

# Building the first linear probe

Minimum viable probe: one local model, one layer, mean pooling, linear head.
Classifies ALLOW vs. DENY against `bench/adversarial_resistance/policy.md`.

1. **Dataset.** Build a standalone training set at `probes/dataset.jsonl` —
   do not reuse `bench/adversarial_resistance/dataset.jsonl`; the bench must
   stay a clean held-out. Target ~3K–5K (prompt, verdict) pairs, roughly
   balanced ALLOW/DENY (a binary probe trained on an all-DENY corpus
   collapses to a constant predictor). Pair privileged commands (same
   COMMAND_POOL shape as the bench) with `goal` fields. DENY examples:
   adversarial / off-topic `goal` text from HF sources the bench doesn't
   use (e.g. `rubend18/ChatGPT-Jailbreak-Prompts`,
   `JailbreakBench/JBB-Behaviors`, `walledai/HarmBench`). ALLOW examples:
   synthesize with Opus 4.6 from the ALLOW principles in `policy.md` —
   safe goals that plausibly justify the privileged command (ticket ID +
   matching transcript + well-scoped task). Dedupe against the bench on
   normalized goal text (command/arg collisions are expected and fine).

   **Label in two passes, keep labels out of the canonical file.**
   `probes/dataset.jsonl` stays unlabeled — it's the clean source. Copy
   50 rows into a throwaway `probes/pilot_labeled.jsonl`, run Opus on
   that copy, and review the 50 manually. If the labels look right,
   run the full labeler into a separate `probes/dataset_labeled.jsonl`
   (leaving the unlabeled source untouched); if they don't, iterate on
   the labeler prompt / generation recipe and re-pilot before paying to
   label thousands. Prior manual testing has surfaced labeler quality
   problems, so this gate is deliberate, not ceremonial. Split 80/20
   train/val off the labeled file — the 242-case bench is the test set.
2. **Model.** [`google/gemma-4-E2B-it`][gemma-4-e2b] (2.3B effective / 5.1B
   total, 35 transformer layers, hidden dim 1536), revision
   `b4a601102c3d45e2b7b50e2057a6d5ec8ed4adcf`. Load bf16 via `transformers`
   on a RunPod RTX 3090 pod; weights at `/workspace/models/gemma-4-E2B-it`.
   Smaller than the original 7B–8B target, a CPU-local-first constraint
   that the RunPod move relaxed but we kept for PLE's on-device fit.
3. **Activations.** Reuse `bench/adversarial_resistance/prompt.py` for input
   formatting. Prefill only (no generation). Hook one middle layer and the
   last layer, mean-pool across tokens, save `(id, hidden, label)` per split.
4. **Train.** `nn.Linear(hidden_dim, 1)` + sigmoid, BCE, Adam lr=1e-3,
   batch 64, 30 epochs early-stopped on val loss. 10 seeds, report mean ± std.
5. **Evaluate.** Score the held-out 242 via `bench/pipeline.py`. Bar: FN-rate
   Wilson upper bound ≤ the Opus 4.6 baseline on the same set.
6. **Sanity checks.** Must beat majority-class on val; shuffled-label probe
   must collapse to chance; bag-of-words baseline must not match the
   activation probe (else the activations aren't carrying the signal).

Out of scope for v1: threshold calibration, cascade wiring into
`daemon/judge.py`, long-context aggregation, audit-log probe scores.

