# Experiment 0010 results

[Experiment registration](../README.md) · [Artifact ledger](../ARTIFACTS.md)

Machine-readable results use `YYYY-MM-DD-<bounded-run-name>.json`. A committed
result is immutable; corrections are new files plus an append-only journal
entry.

`execution.json` is the first model execution. It retains source-derived
projections, all registered scenario traces, and exact metrics. The result is
canonical JSON and is independently recomputed by the Rust research checker.
It deliberately does not claim forced-fresh cache agreement.

`forced-fresh-smoke.json` retains the subsequent clean-worktree baselines,
external holdout outcomes, and two auxiliary load-bearing mutations. It also
records that the required change matrix is incomplete and that the Lean route
remains unanswered.

`revision-falsifier.json` is the decisive executable counterexample. A checker
reads an undeclared file: declared-only identity permits stale reuse, while a
global revision identity invalidates an unrelated unit. The experiment is
therefore concluded with the candidate rejected rather than left pending.
