# Experiment 0025 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path or retained object | State | Purpose |
|---|---|---|---|
| EXP-0025-R001 | `README.md` | preregistered, then conclusion appended | Questions, candidate boundary, and immutable decision rule |
| EXP-0025-R002 | `preregistration.json` | frozen | Machine-readable Windows confirmation contract and 30 attacks |
| EXP-0025-C001 | `candidate.json` | frozen before retained confirmation; candidate payload `sha256:4bf2040c0c42f183796eb563113372f50f8f113170914c864da9d56e1a3fb47e` | Discovery-derived initialization candidate |
| EXP-0025-I001 | `.github/workflows/platform-enforcement-research.yml` | executed | Native `windows-11-arm` orchestration and independent validation |
| EXP-0025-I002 | `python/proofbound/windows_native_boundary.py` | executed | Native AppContainer, token, job, desktop, ACL, alias, capture, and cleanup boundary |
| EXP-0025-I003 | `python/proofbound/windows_initialization_{execute,research,attacks,confirmation}.py` | executed | Confirmation orchestration, independent Python validation, attacks, and decision |
| EXP-0025-I004 | `crates/proofbound-ir-prototype/src/windows_initialization.rs` | executed | Independent Rust validation and adversarial interpretation |
| EXP-0025-E001 | retained `capture.json` from [run 33822698555](https://github.com/bordumb/proof-bound/actions/runs/33822698555), 446,835 bytes, `sha256:788ac34ab729a1efb40ee9d9b28e0365ac3c95c893353fdfa6a9eeaa1fa7aee3` | immutable external run artifact | Complete 51-slot raw native capture; omitted from Git because the retained run binds it exactly |
| EXP-0025-E002 | `results/report.json`; retained validator reports each 4,043 bytes, `sha256:c6353e8c0a3387818c031bd4e0ff3146a6d2c846948855007253374a65a797d3` | canonical checked-in result plus byte-identical external Python/Rust artifacts | Independent semantic interpretation and Q1--Q5 values |
| EXP-0025-E003 | `results/attacks.json`; retained attack reports each 3,305 bytes, `sha256:03262296e05c8c9019effb7ed0e203d1ae19e9f062bc896a9e9f92a2db91bbf2` | canonical checked-in result plus byte-identical external Python/Rust artifacts | Thirty exact adversarial classifications |
| EXP-0025-E004 | `results/execution.json`, retained payload 1,151 bytes, `sha256:4ad22d37227556486e5f8240c442bba31aaaf896660ac2d97f87c6766402e426` | canonical checked-in result | Final `revise` decision and execution identity `sha256:9483487867549fb6d2966e07f8664e503d2f14c4c57706caa173977c2a04881d` |
| EXP-0025-D001 | `CONCLUSION.md` | concluded | Interpretation, limitations, and successor requirements |

The raw capture and 30 per-attack capture copies are retained in the workflow
artifact rather than duplicated in Git. Their identities, sizes, validator
agreement, and freshness are bound by `results/execution.json`. The compact
checked-in JSON files are canonical payload copies; Git's final newline is not
part of the retained artifact sizes or hashes listed above.
