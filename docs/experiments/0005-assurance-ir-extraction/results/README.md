# Experiment 0005 results

[Experiment registration](../README.md) · [Artifact ledger](../ARTIFACTS.md)

Machine-readable results use:

```text
YYYY-MM-DD-<bounded-run-name>.json
```

Each result must include its schema, experiment ID, exact Proofbound commit,
corpus identity, implementation identity, environment summary, registered
metrics, and referenced artifact digests. A committed result is immutable;
corrections are new files plus an append-only journal entry.

| Run | Status | Scope |
|---|---|---|
| [Initial projection parity](2026-09-01-initial-projection-parity.json) | complete, bounded | Twenty positive source projections and 15 canonical domain vectors; no preregistered adversarial execution or full status rederivation |
| [Adversarial evidence algebra](2026-09-02-adversarial-evidence-algebra.json) | complete, bounded | Independent Rust/Python validation of 20 positive cases, all 20 corrected preregistered attacks, 15 canonical vectors, and seven exact status rederivations |
| [Q1 forward-projection progress](2026-09-02-q1-forward-projection-progress.json) | complete progress run; Q1 still failed | Complete forward reconstruction for the frozen portable fixture, semantic reverse comparisons for registered claims and requests, and matched policy-omission and provenance-substitution attacks |
| [Q1 losslessness decision](2026-09-02-q1-losslessness-decision.json) | complete decision run; Q1 failed | Twenty positive reverse projections, twelve exact matched programme attacks, and a sixteen-row re-audit finding nine complete and seven partial rows |
