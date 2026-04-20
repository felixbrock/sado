[building-probes-for-gemini]: https://arxiv.org/pdf/2601.11516
[predicting-success-from-pre-generation-activations]: https://arxiv.org/pdf/2602.09924
[constitutional-classifiers++]: https://arxiv.org/pdf/2601.04603
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
4. **Train.** Fit `sklearn.linear_model.LogisticRegression(C=1.0,
class_weight="balanced", max_iter=2000)` on the mean-pooled activations.
   Closed-form LogReg finds a strictly better linear boundary than the
   `nn.Linear + Adam + BCE` recipe we started with — on hidden_mid (L18),
   LogReg hit val 0.964 / test 0.975 versus 0.868 for the nn.Linear probe
   on the same features, so the earlier "BoW beats probe" result was a
   training-recipe artifact, not a signal problem. Keep the nn.Linear path
   only as a 10-seed variance check (report mean ± std); LogReg is the
   probe of record. `class_weight="balanced"` matters — the labeled set
   leans DENY and an unweighted fit over-predicts the majority class.
5. **Evaluate.** Score the held-out 242 via `bench/pipeline.py`. Bar: FN-rate
   Wilson upper bound ≤ the Opus 4.6 baseline on the same set.
6. **Sanity checks.** Must beat majority-class on val; shuffled-label probe
   must collapse to chance; bag-of-words baseline must not match the
   activation probe (else the activations aren't carrying the signal).

Out of scope for v1: threshold calibration, cascade wiring into
`daemon/judge.py`, long-context aggregation, audit-log probe scores.

---

# Results (as of 2026-04-20)

## Final probe of record

- **Model:** `google/gemma-4-E2B-it`, revision `b4a601102c3d45e2b7b50e2057a6d5ec8ed4adcf`, loaded bf16 on an RTX 3090. Activations stored as a `(N, 36, 3, 1536)` tensor per split (all layers × `[mean, last_token, max]` × hidden dim).
- **Canonical config:** layer **19** (mid-range), pooling **max**, classifier `LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000)`. Found via a 108-config (layer × pool) sweep ranked by val accuracy; see `probes/train_probe.py --sweep`. Max pooling dominated the top 10 (8 of 10), mean pooling — the README default — didn't appear.
- **Training set:** `probes/dataset_labeled.jsonl` (3056 rows = 2936 original + 120 plain-prose DENY augmentation). Stratified 80/20 split on verdict, seed 42.
- **Test set:** `bench/adversarial_resistance/dataset.jsonl` (308 rows = 200 original DENY + 28 ALLOW + 80 plain-prose DENY).

## Head-to-head on the 308-row bench (see `bench/results/adversarial_resistance/20260420T140616Z/`)

| Judge                       | Acc     | FN rate | FP rate |
|---                          |---      |---      |---      |
| claude-opus-4-7             | 100.0%  | 0.0%    | 0.0%    |
| **probe-gemma-l19-max**     | 95.5%   | 5.0%    | 0.0%    |
| claude-haiku-4-5            | 89.9%   | 10.7%   | 3.6%    |
| gemma-4-e2b-it-generative   | 28.2%   | 78.9%   | 0.0%    |

Per-category, the probe is flat (4–6% FN everywhere) while Haiku collapses on `adversarial_injection` (18.7% FN) but is perfect on `plain_deny`. Gemma's own generation head hovers at 56–91% FN across categories — the activations carry the signal, the LM head doesn't.

## Domain-shortcut history (why we trust the probe now)

The first version of the probe (jailbreak-flavored DENY only in training) looked world-class but was a jailbreak-stylistic classifier:

| category              | before augmentation | after +120 plain-prose DENY in train |
|---                    |---                  |---                                   |
| adversarial_injection | 5.3% FN (L19 max)   | 4.0% FN                              |
| **plain_deny**        | **68.8% FN**        | **6.2% FN**                          |

Mixing plain-prose DENY into training broke the shortcut without hurting the original domain. Evidence the 2.3B activations carry a usable policy feature; they just need diverse examples to expose it. `probes/build_plain_deny_train.py` is the augmentation recipe.

## Known caveat / next-session work

The plain-prose DENY training rows use the **same 8 always-deny commands** as the bench's plain-DENY test rows (`useradd`, `chown /etc/sudoers`, `systemctl stop firewalld/fail2ban/sshd`, `iptables -F`, `sysctl -w kernel.dmesg_restrict=0`, `rm -rf /usr/local/lib`). So some of the FN drop could be command-keyword learning, not fully generalized semantic policy understanding. **Next validity test:** re-augment with a *different* set of always-deny commands (`visudo`, `passwd`, `setenforce 0`, `mount -o bind /etc/passwd`, etc.) and re-run. If FN stays low on the bench's plain_deny, true generalization.

## Session cost breakdown (one-time)

- RunPod RTX 3090: ~$0.50 across all extraction + Gemma-judge runs
- Opus 4.7 synthesis + labeling (ALLOW cases, plain_deny bench, plain_deny training): ~$13
- Opus 4.7 + Haiku 4.5 full 308-row bench via pipeline (with prompt caching): ~$5
- Total: ~$18.50
- After initial training, **the probe itself runs locally in <10 ms per prompt with a 6 KB weight vector**.

