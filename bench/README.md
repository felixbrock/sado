# Guidelines

A benchmark is a measurement instrument. Like any instrument, its value
depends on whether it measures what it claims to, whether the measurement
is stable, and whether the result is actionable. The points below are what
we try to hold ourselves to when building benchmarks in this repo — with
extra weight on non-verifiable domains (safety, judgment, policy, writing
quality), where there is no compiler or unit test to settle the question.

Two concerns, kept separate on purpose. **Dataset** guidelines govern the
data itself — what it contains, how it's constructed, and what it rules
out. **Pipeline** guidelines govern everything downstream of the data —
how the model is called, how the output is scored, and how results are
reported. A perfect dataset scored by a sloppy pipeline produces
meaningless numbers; a careful pipeline running over a bad dataset
produces precise meaningless numbers. Both have to be right. Items tagged
_non-verifiable_ below are either specific to, or sharply more important
in, domains with no ground-truth oracle.

## Dataset-related dimensions

1. **Construct validity — measure the thing, not a shadow of the thing.**
   Name the property under test in one sentence, then ask whether any
   other variable could plausibly explain a score change. The
   `adversarial_resistance` dataset holds every other input weak so that
   only `goal` varies; that isolation is the point. Without it, a "safety"
   score can drift into measuring formatting, verbosity, or refusal
   tendency instead.
   _Raji et al., "AI and the Everything in the Whole Wide World Benchmark"
   (NeurIPS 2021); Liang et al., HELM (2022)._

2. **Difficulty calibration.** A dataset where every model scores 99% (or
   1%) tells you nothing. Aim for current frontier models somewhere in
   the middle of the curve, and retire or harden the dataset once it
   saturates. Ceiling effects silently neutralize otherwise well-designed
   benchmarks.

3. **Contamination resistance.** Assume any public dataset is already in
   pre-training. Prefer held-out splits, novel synthesis, or adversarial
   regeneration. Where we reuse public sources (e.g.
   `deepset/prompt-injections`), we do so knowing the model may have seen
   them — and we interpret results accordingly (a failure here is very
   damning; a pass is weaker evidence than on unseen data).
   _Oren et al., "Proving Test Set Contamination in Black Box Language
   Models" (2023); BIG-Bench canary strings, Srivastava et al. (2022)._

4. **Controls against shortcut learning.** Every positive case should have
   a matched negative that blocks the trivial heuristic. The
   `benign_control` entries exist so a model that simply pattern-matches
   "suspicious-looking text → DENY" cannot fake competence. If your
   dataset has no controls, you are probably measuring a shortcut.
   _Ribeiro et al., "CheckList" (ACL 2020)._

5. **Distributional realism.** The input distribution of the benchmark
   should resemble the input distribution of deployment. A policy
   enforcer will see clipped transcripts, partial goals, weirdly-cased
   args, and multilingual prompts in the wild — the dataset should too.
   Toy-clean inputs give toy-clean scores.

6. **Tagging for debuggability.** Every entry should carry the metadata
   needed to slice the results later: category, difficulty, source,
   sub-capability. Tagging is a dataset-side obligation; surfacing the
   slices is a pipeline-side obligation (see below). Without tags the
   pipeline has nothing to slice.

7. **Engineer verifiability in.** _(non-verifiable)_ The cleanest trick
   is to constrain the task so the answer becomes checkable without
   losing the property under test. `adversarial_resistance` does this by
   making _every_ case a DENY: the judgment is still subtle, but the
   scoring is binary. When you can collapse a fuzzy question into a
   defensible label, do it at the dataset level rather than papering
   over it with a judge later.

8. **Adversarial and red-teamed augmentation.** _(non-verifiable)_ For
   safety-adjacent evals, static datasets age quickly as models learn
   to pass them. Mix in model-written and human-written adversarial
   cases; rotate the held-out slice across releases rather than
   freezing a single version forever.
   _Perez et al., "Discovering Language Model Behaviors with Model-Written
   Evaluations" (2022); Ganguli et al., "Red Teaming Language Models to
   Reduce Harms" (2022)._

9. **Private hold-out against Goodhart.** _(non-verifiable)_ Once a
   number drives decisions, it stops being a measurement and starts
   being a target. Keep a portion of the dataset out of the repo — or
   out of reach of anyone tuning against the score — for final checks,
   and treat the public portion as the development set.
   _Goodhart (1975); Amodei et al., "Concrete Problems in AI Safety"
   (2016)._

## Pipeline-related dimensions

1. **Statistical honesty.** Small eval sets produce noisy comparisons.
   Report sample size, confidence intervals, and — when comparing two
   models — whether the gap is within run-to-run noise. Prefer paired
   scoring (same inputs, different models) over single-run point
   estimates. For binary outcomes near 0 or 1, Wilson intervals are
   preferred over normal-approximation or bootstrap (both degenerate at
   the edges).
   _Miller, "Adding Error Bars to Evals" (2024); Biderman et al.,
   "Lessons from the Trenches on Reproducible Evaluation of Language
   Models" (2024)._

2. **Actionable failure surface.** The pipeline's job is to turn raw
   per-entry outputs into something a human can debug. Report per-
   category accuracy, separate buckets for model errors and parse
   errors (never silently fold either into the "correct" verdict),
   and make per-entry traces inspectable. A single aggregate number is
   a dashboard metric, not a debugging tool.

3. **Rubric-based LLM-as-judge, not vibes.** _(non-verifiable)_ If a
   human-scored rubric exists, an LLM judge can approximate it; if
   not, the judge is rating taste. Spell out criteria explicitly,
   validate on a human-labeled subset, and report judge-human
   agreement (Cohen's κ or equivalent). Single-judge preference scores
   correlate with verbosity and style, not quality.
   _Zheng et al., "Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena"
   (NeurIPS 2023)._

4. **Paired comparisons over absolute scores.** _(non-verifiable)_
   Humans (and LLM judges) are more reliable at "A better than B"
   than at "this is a 7/10". Bradley–Terry-style aggregation is
   typically more stable than averaging Likert scores, and the
   pipeline should be structured to emit pairwise outcomes when the
   task permits.

5. **Human calibration checks.** _(non-verifiable)_ Even a small
   human-labeled slice (50–200 items) is enough to detect when an
   automated metric has decoupled from the underlying construct.
   Re-run this calibration whenever the metric, the judge model, or
   the rubric changes — it's the only defense against silent drift
   between "what we measure" and "what we care about."

6. **Multi-dimensional reporting.** _(non-verifiable)_ No single scalar
   captures "is this model good." HELM's insight — report accuracy,
   calibration, robustness, fairness, toxicity, efficiency as separate
   axes — applies to any non-verifiable eval. A model that is safer
   but much slower is a different product, not a strictly better one.
   _Liang et al., HELM (2022)._

# Pipeline quality rating

How the shared pipeline (`bench/pipeline.py`, `bench/models/`) stacks up
against the pipeline-related dimensions above. Applies to every benchmark
that runs through it; per-dataset ratings live in each benchmark's README.

Rating scale: **strong** = in place, **partial** = present but incomplete,
**weak** = known gap, **N/A** = does not apply to the current benchmark
surface.

| # | Dimension                     | Rating  | Evidence                                                                                                                                                  | Gap / next step                                                                                                              |
| - | ----------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 1 | Statistical honesty           | partial | Wilson 95% CIs on accuracy and FN rate (`pipeline.py:wilson_ci`); per-model JSON summary with sample size                                                 | No multi-seed runs; temperature/sampling not pinned in `Opus46` adapter; no paired bootstrap when comparing two models       |
| 2 | Actionable failure surface    | strong  | Per-category FN/FP; model errors and parse errors in distinct buckets, never folded into the verdict (`pipeline.py:summarize`); per-entry JSONL traces    | Slices are hand-tagged at the dataset level; no automatic sub-capability clustering                                          |
| 3 | Rubric-based LLM-as-judge     | N/A     | No judge in current pipeline — scoring is a mechanical JSON parse against ground-truth labels                                                             | Applies if a future benchmark is open-ended; would need rubric definition + human agreement checks before use                |
| 4 | Paired comparisons            | N/A     | Current benchmark is binary ALLOW/DENY; no preference scoring                                                                                             | Applies if a future benchmark scores open-ended outputs; pipeline would need a pairwise aggregator (Bradley–Terry or Elo)    |
| 5 | Human calibration checks      | N/A     | No automated judge / proxy metric to calibrate against yet                                                                                                | Becomes required the moment a judge is introduced; also worth using for dataset label spot-checks                            |
| 6 | Multi-dimensional reporting   | partial | Emits accuracy, FN, FP, FN rate (+CI), parse errors, model errors, latency, per-category breakdowns                                                       | No robustness axis (paraphrase variance), no reason-quality / calibration axis, no cost-per-call or throughput reporting     |
