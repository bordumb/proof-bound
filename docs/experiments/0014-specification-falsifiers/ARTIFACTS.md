# Experiment 0014 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0014-R001 | `README.md` | preregistration revision 1, `sha256:9c7bf5a6c903e07ad5104e409a69d2fa0d2596bc13d03cbf9cc7446c6a91a2c9` | Human questions, candidate, measurements, attacks, scope, and procedure |
| EXP-0014-R002 | `preregistration.json` | preregistration revision 1, `sha256:affaecd5376108f96492db1832104e6f6e94a0899747cd33aded163af7de08e2` | Machine-readable questions, repetition count, and exact attack codes |
| EXP-0014-C001 | `corpus/universe.json` | frozen, `sha256:eb2c6094ae4b1e408604a9614f3e0991e9c60f020a55b0f9f3bc954922521e02` | External finite carriers, typed variables, required roles, and required mutants |
| EXP-0014-C002 | `corpus/contracts.json` | frozen, `sha256:451922792869c32abb622891aaca10da2cff45e15b8f9ff65edc128c5d938735` | Five typed parser-property contracts bound to the universe bytes |
| EXP-0014-C003 | `corpus/execution-tables.json` | frozen, `sha256:8d0bedd2e3887cc30174631486a703412c5260aa4a2285c3d458fba5c1935a12` | Explicit correct and six-mutant result rows for all 14 carrier cases |
| EXP-0014-C004 | `corpus/attacks.json` | frozen, `sha256:b768c253cc24c33817b6ab8773c092546cf5298b4919e2d2bd6295e90caa4747` | Twenty registered structural, vacuity, adequacy, identity, and ordering attacks |
| EXP-0014-C005 | `corpus/expected.json` | frozen, `sha256:0470052e53dcebb0bc89e22e0a871934b4edee966401652a98ba88232230ac55` | Counts, ten repetitions, and AST/carrier/contract/report ceilings |
| EXP-0014-C006 | `corpus/CONTRACT.md` | frozen, `sha256:cd1d9d98a9ec4a5558f81ed08356f6161ce525b2b3a4da62725f0ce46c856963` | Closed typing, evaluation, adequacy, identity, and oracle-opening contract |
| EXP-0014-I001 | `crates/proofbound-ir-prototype/src/specifications.rs` | implemented | Typed Rust corpus validator, expression checker/evaluator, adequacy report derivation, and exact attack executor |
| EXP-0014-I002 | `crates/proofbound-ir-prototype/src/main.rs` | implemented | Research-only `execute-specifications` command |
| EXP-0014-I003 | `python/proofbound/specifications_research.py` | implemented independently | Python closed-record/type validator, table evaluator, report validator, and attack executor |
| EXP-0014-I004 | `python/tests/test_specifications_research.py` | passing | Correct/mutant adequacy, all exact attacks, and self-consistent counterexample substitution |
| EXP-0014-I005 | `python/proofbound/specifications_experiment.py` | implemented | Post-execution expected-value and complexity evaluator for Q1--Q5 |
| EXP-0014-I006 | `python/tests/test_specifications_experiment.py` | pending retained result | Metric and retained-result regression checks |
| EXP-0014-E001 | `results/` | reserved | Immutable execution and comparison report |
