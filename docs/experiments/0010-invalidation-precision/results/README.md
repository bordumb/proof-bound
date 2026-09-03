# Experiment 0010 results

[Experiment registration](../README.md) · [Artifact ledger](../ARTIFACTS.md)

Machine-readable results use `YYYY-MM-DD-<bounded-run-name>.json`. A committed
result is immutable; corrections are new files plus an append-only journal
entry.

`execution.json` is the first model execution. It retains source-derived
projections, all registered scenario traces, and exact metrics. The result is
canonical JSON and is independently recomputed by the Rust research checker.
It deliberately does not claim forced-fresh cache agreement, which remains a
separate required stage before the experiment can be concluded.
