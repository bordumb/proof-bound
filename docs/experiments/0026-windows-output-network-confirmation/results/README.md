# Experiment 0026 checked-in results

These compact payloads are canonical copies from
[GitHub run 33827784782](https://github.com/bordumb/proof-bound/actions/runs/33827784782):

- `execution.json` records the final `revise` decision, question values,
  metrics, identities, and validator agreement;
- `report.json` is the byte-identical semantic report emitted independently by
  Python and Rust; and
- `attacks.json` is their byte-identical exact classification of all 38
  registered mutations.

The 451,027-byte raw capture and per-attack mutated captures remain in the
retained workflow artifact. They are not checked into Git because the compact
execution payload already binds their hashes and agreement. See the
[artifact ledger](../ARTIFACTS.md) for exact sizes and identities.
