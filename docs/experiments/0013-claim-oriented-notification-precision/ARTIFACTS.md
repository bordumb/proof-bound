# Experiment 0013 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0013-R001 | `README.md` | preregistration revision 1, `sha256:45f17cce332126ffe68b956ca7d7a058a8628eacdff950dc7fad77bd7c3985d6` | Human questions, candidate, metrics, attacks, scope, and procedure |
| EXP-0013-R002 | `preregistration.json` | preregistration revision 1, `sha256:f6ed291eddbd95faf7e1b3d1a376759de9e71e00c9a17af33c41e13ce8266efa` | Machine-readable questions, repetitions, and exact attack codes |
| EXP-0013-C001 | `corpus/scenarios.json` | frozen, `sha256:79813215ac2bbaca0e0a53fcaaa4e952eb12fe2ec37217b457d46307bb8d7939` | Six scenarios, 20 findings, claims, facts, and impact paths |
| EXP-0013-C002 | `corpus/oracle.json` | frozen, `sha256:5e701c73835d947431608a1325f27c3b81244e90442fb1cd53322b562a2f962a` | Six exact critical action tuples withheld from engines |
| EXP-0013-C003 | `corpus/attacks.json` | frozen, `sha256:43877f39eb383abf978bac9fe89295f6fe419ad9e0a9cebc0533f9a97734d52f` | Twenty registered category, integrity, grouping, and suppression attacks |
| EXP-0013-C004 | `corpus/expected.json` | frozen, `sha256:193e6e4d68454ae29c7f26cac2dfc2db0284bddaa622a735182b3611933111b6` | Counts, threshold, categories, repetitions, and participant minimum |
| EXP-0013-C005 | `corpus/instrument.json` | frozen, `sha256:6eb20f6fd634e6b42836debe14b788d40bbbc6a626b7b4d9146b6adac9040a0f` | Counterbalanced optional human study with no responses |
| EXP-0013-C006 | `corpus/CONTRACT.md` | frozen, `sha256:7d86076d2eaf668bd5c7b81c9979980563427534546b6aefca89a6392ebcb477` | Closed input, grouping, identity, metric, and human-evidence rules |
| EXP-0013-I001 | `crates/proofbound-ir-prototype/src/notifications.rs` | implemented | Typed Rust uncertainty validator, baseline and candidate derivation, canonical report validator, and attack executor |
| EXP-0013-I002 | `crates/proofbound-ir-prototype/src/main.rs` | implemented | Research-only `execute-notifications` command |
| EXP-0013-I003 | `python/proofbound/notifications_research.py` | implemented independently | Python closed-record validator, decision derivation, canonical identity checker, and attack executor |
| EXP-0013-I004 | `python/tests/test_notifications_research.py` | passing | Independent derivation, low-severity dependency, and self-consistent path-substitution checks |
| EXP-0013-E001 | `results/` | reserved | Immutable machine and any eligible participant results |
