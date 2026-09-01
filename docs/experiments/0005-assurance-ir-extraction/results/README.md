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
