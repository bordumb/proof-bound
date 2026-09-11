# Experiment 0018 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0018-R001 | `README.md` | preregistered | Questions, candidate boundary, measurements, scope, and decision rule |
| EXP-0018-R002 | `preregistration.json` | preregistered | Machine-readable subject, platform candidate, attacks, and ceilings |
| EXP-0018-C001 | `corpus/index.json` | frozen, `sha256:9686074a5cd8e5f2b3f0018ab95104f697bce292e0e948482220ec378780bd43` | Exact inventory of the frozen subjects, contract, inputs, expected values, and intentional absence |
| EXP-0018-C002 | `corpus/contract.json` | frozen, `sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d` | Backend-neutral operation and abstract enforcement policy |
| EXP-0018-C003 | `corpus/expected.json` | frozen, `sha256:7a5c4e50e3374249f9e696814f28cdcaa240fc97a3293d7598f6918527b4f876` | Counts, output identity, repetitions, and complexity ceilings |
| EXP-0018-I001 | `crates/proofbound-ir-prototype/src/enforced.rs` | concluded, 1,797 nonblank lines | Typed Seatbelt policy generator, cross-language runner, receipt validator, invalidation derivation, and 30 exact adversarial checks |
| EXP-0018-I002 | `python/proofbound/enforced_effects_research.py` | implemented, 758 nonblank lines | Independent receipt, policy, attack, and invalidation validator |
| EXP-0018-E001 | `results/capture.json` | retained, `sha256:1e82a1696fdfc24a5676c26205781029b2b6573d7d6d3596e9393ec0d4df4c70` | Canonical raw 30-run, 21-probe macOS capture with 93,574 ms measured wall time |
| EXP-0018-E002 | `results/rust-report.json` | retained, `sha256:0b886c934752605f068dde145c52ef77f15e21bb938a688776621f71792b78f0` | Rust-derived semantic and adversarial report |
| EXP-0018-E003 | `results/python-report.json` | retained, `sha256:0b886c934752605f068dde145c52ef77f15e21bb938a688776621f71792b78f0` | Independently derived byte-identical Python report |
| EXP-0018-E004 | `results/execution.json` | retained, `sha256:6920524ef537842076a74caeac50451c09a981297d11e3896f0520479a0a8503` | Final `revise` decision: Q1--Q4 pass; Q5 fails its wall-time criterion |
| EXP-0018-D001 | `CONCLUSION.md` | concluded | Interpretation, limitations, language implications, and next research |
