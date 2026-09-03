# Experiment 0011 results

[Experiment registration](../README.md) · [Artifact ledger](../ARTIFACTS.md)

Machine-readable results use immutable canonical JSON. Corrections receive a
new result file and append-only journal entry rather than overwriting an
observed run.

| Artifact | SHA-256 | Meaning |
|---|---|---|
| [`execution.json`](execution.json) | `926d897ac28f790dd0de30c88d068720ffe42b2cea7bb8d9fbe324cb0d9bef25` | Ten-run Rust/Python differential compilation, restricted Pkl evaluation, frozen controls, 22 attacks, metrics, and Q1–Q5 outcomes |

The result is negative as a confirmatory experiment. All nine Rust/Python
implementation pairs agree byte-for-byte and all 22 attacks reject with the
registered code, but none of the three frozen programme hashes match the
canonical bytes they were meant to control. The registered byte lengths do
match. The report retains both expected and observed identities instead of
rewriting the frozen corpus.
