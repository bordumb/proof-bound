# Experiment 0026 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path or retained object | State | Purpose |
|---|---|---|---|
| EXP-0026-R001 | `README.md` | preregistered, then conclusion appended | Questions, candidate boundary, and immutable decision rule |
| EXP-0026-R002 | `preregistration.json` | frozen | Machine-readable output/network contract and 38 attacks |
| EXP-0026-C001 | inherited EXP-0025 `candidate.json` | frozen; candidate payload `sha256:4bf2040c0c42f183796eb563113372f50f8f113170914c864da9d56e1a3fb47e` | Exact Windows initialization candidate |
| EXP-0026-I001 | `.github/workflows/platform-enforcement-research.yml` | executed | Native `windows-11-arm` orchestration, validation, attacks, and retention |
| EXP-0026-I002 | `python/proofbound/windows_native_boundary.py` | executed | Native AppContainer boundary and loopback-exemption query |
| EXP-0026-I003 | `python/proofbound/windows_output_network_{execute,research,attacks,confirmation}.py` | executed | Orchestration, Python interpretation, attacks, and decision |
| EXP-0026-I004 | `crates/proofbound-ir-prototype/src/windows_output_network.rs` | executed | Independent Rust validation and adversarial interpretation |
| EXP-0026-E001 | retained `capture.json` from [run 33827784782](https://github.com/bordumb/proof-bound/actions/runs/33827784782), 451,027 bytes, `sha256:7548d6bce1063ba110f0740ed19000103f3c1b08491d30628ef6f33a67836ecb` | immutable external run artifact | Complete raw native capture; omitted from Git because the retained run binds it exactly |
| EXP-0026-E002 | `results/report.json`; retained validator reports each 5,081 bytes, `sha256:5e163f52e734cd31a9ed8c53c94f0745112d8f726eed119777b77eb8a43ac909` | canonical checked-in result plus byte-identical external Python/Rust artifacts | Independent semantic interpretation and Q1--Q5 values |
| EXP-0026-E003 | `results/attacks.json`; retained attack reports each 4,181 bytes, `sha256:1a41d44b3e584d41b7c65a6e12071781395ae1d1bc088ceca8c3d40d01f47b88` | canonical checked-in result plus byte-identical external Python/Rust artifacts | Thirty-eight exact adversarial classifications |
| EXP-0026-E004 | `results/execution.json`, retained payload 1,306 bytes, `sha256:f5ed99e6c5495ad15aeb68ed14be32bfb488a15662fe23732e7f7b30b5018236` | canonical checked-in result | Final `revise` decision and execution identity `sha256:3846987c88f31d536f76b4d236192be4f815c1fdd72710b7a89385aa32d28a31` |
| EXP-0026-D001 | `CONCLUSION.md` | concluded | Interpretation, limitations, and successor requirements |

The raw capture and 38 per-attack capture copies are retained in the workflow
artifact rather than duplicated in Git. Their identities, validator agreement,
and freshness are bound by `results/execution.json`. The compact checked-in
JSON files are canonical payload copies; Git's final newline is not part of the
retained artifact sizes or hashes listed above.
