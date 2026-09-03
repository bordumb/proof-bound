# Experiment 0017 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0017-R001 | `README.md` | preregistered | Questions, migration model, measures, scope, and procedure |
| EXP-0017-R002 | `preregistration.json` | preregistered | Machine-readable subject, runtimes, attacks, counts, and ceilings |
| EXP-0017-C001 | `corpus/contract.json` | frozen, `sha256:8ef40f6b809c73094d7ad7ebddd2af7310b4354c8eaa7e5cfdd74b71ed20b094` | Backend-neutral foreign ABI and policy |
| EXP-0017-C002 | `corpus/cases.json` | frozen, `sha256:a53af172b7778d74d1f8e1b84590905571c5f12f562fa7b52872caad5ce3fc9f` | Exact encode/decode inputs and expected outputs |
| EXP-0017-C003 | `corpus/graphs.json` | frozen, `sha256:76819bea65757b090ac058443a6f8960c3d0d7e5cd52d420b947fab31d019ae8` | Baseline and migrated mixed claim graphs |
| EXP-0017-C004 | `corpus/attacks.json` | frozen, `sha256:a44b9aabc22bda7c99f721e4eb7874f8072d5ead9920d130a34df1bac0b274ee` | Thirty exact ABI, observation, graph, and integrity attacks |
| EXP-0017-C005 | `corpus/expected.json` | frozen, `sha256:efd6b8686013ef1326bcc064391d57379e309046db68f65695eaede705410f41` | Counts, migration set, and complexity ceilings |
| EXP-0017-I001 | `subjects/python_caller.py` | absent | Independent Python legacy/native caller |
| EXP-0017-I002 | `subjects/typescript_caller.mjs` | absent | Independent TypeScript/Node legacy/native caller |
| EXP-0017-I003 | `crates/proofbound-ir-prototype/src/migration.rs` | absent | Rust mixed-graph kernel and attack executor |
| EXP-0017-I004 | `python/proofbound/migration_research.py` | absent | Independent Python mixed-graph kernel |
| EXP-0017-E001 | `results/execution.json` | absent | Retained two-language execution and Q1--Q5 decisions |
