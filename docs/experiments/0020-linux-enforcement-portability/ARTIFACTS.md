# Experiment 0020 artifact ledger

| ID | Path | State | Purpose |
|---|---|---|---|
| EXP-0020-R001 | `README.md` | preregistered, concluded | Questions, scope, ceilings, and decision rule |
| EXP-0020-R002 | `preregistration.json` | preregistered | Machine-readable frozen Linux contract |
| EXP-0020-S001 | EXP-0018 contract | frozen external input | Exact backend-neutral effect contract |
| EXP-0020-I001 | `instrument/Dockerfile` | concluded | Digest-pinned Linux research environment; not an enforcement mechanism |
| EXP-0020-I002 | `instrument/linux_enforcer.c` | concluded | Native Landlock, `no_new_privs`, and seccomp launcher/probe |
| EXP-0020-I003 | `crates/proofbound-ir-prototype/src/linux_enforcement.rs` | concluded, 716 nonblank lines | Independent Rust policy compiler and validator |
| EXP-0020-I004 | `python/proofbound/linux_enforcement_research.py` | concluded, 451 nonblank lines | Independent Python policy compiler and validator |
| EXP-0020-E001 | `results/capture.json` | retained, `sha256:7a6da3dde2f307ba5d9e10b668e4ec116160fd7c66fb18516af1482f5de58380` | Raw typed unsupported capture; zero workload receipts |
| EXP-0020-E002 | `results/rust-report.json` | retained, `sha256:fd01653315c99993423dbbea9d38eda461389f3a2bee71b307cfa181669b1d07` | Rust-derived report |
| EXP-0020-E003 | `results/python-report.json` | retained, `sha256:fd01653315c99993423dbbea9d38eda461389f3a2bee71b307cfa181669b1d07` | Byte-identical Python-derived report |
| EXP-0020-E004 | `results/execution.json` | retained, `sha256:404cb21891f53019e0d8dcfa37f01b7245155284ddb13b337b8f0983d558fd97` | Final five-question `unanswered` decision |
| EXP-0020-D001 | `CONCLUSION.md` | concluded | Interpretation and confirmatory-run requirement |
