# Experiment 0018 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0018-R001 | `README.md` | preregistered | Questions, candidate boundary, measurements, scope, and decision rule |
| EXP-0018-R002 | `preregistration.json` | preregistered | Machine-readable subject, platform candidate, attacks, and ceilings |
| EXP-0018-C001 | `corpus/index.json` | frozen, `sha256:9686074a5cd8e5f2b3f0018ab95104f697bce292e0e948482220ec378780bd43` | Exact inventory of the frozen subjects, contract, inputs, expected values, and intentional absence |
| EXP-0018-C002 | `corpus/contract.json` | frozen, `sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d` | Backend-neutral operation and abstract enforcement policy |
| EXP-0018-C003 | `corpus/expected.json` | frozen, `sha256:7a5c4e50e3374249f9e696814f28cdcaa240fc97a3293d7598f6918527b4f876` | Counts, output identity, repetitions, and complexity ceilings |
| EXP-0018-I001 | `crates/proofbound-ir-prototype/src/enforced.rs` | implemented, not yet concluded | Typed Seatbelt policy generator, cross-language runner, receipt validator, invalidation derivation, and 30 exact adversarial checks |
| EXP-0018-I002 | Python validator | not created | Independent receipt and invalidation validator |
| EXP-0018-E001 | `results/execution.json` | not created | Retained execution and question decisions |
