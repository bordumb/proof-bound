# Experiment 0027 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path or retained object | State | Purpose |
|---|---|---|---|
| EXP-0027-R001 | `README.md` | preregistered, then status and links appended | Questions, candidate boundary, and immutable decision rule |
| EXP-0027-R002 | `preregistration.json` | frozen | Machine-readable WFP contract and 48 attacks |
| EXP-0027-I001 | `.github/workflows/platform-enforcement-research.yml` | executed | Native Windows orchestration, differential validation, attacks, and retention |
| EXP-0027-I002 | `instrument/wfp_observer.rs` | executed and identity-bound | Read-only WFP query, subscription, and event capture |
| EXP-0027-I003 | `python/proofbound/windows_wfp_{execute,research,attacks,confirmation}.py` | executed | Orchestration, Python validation, attacks, and decision |
| EXP-0027-I004 | `crates/proofbound-ir-prototype/src/windows_wfp.rs` | executed | Independent Rust validation and adversarial interpretation |
| EXP-0027-E001 | retained `capture.json` from [run 33844439146](https://github.com/bordumb/proof-bound/actions/runs/33844439146), 457,009 bytes, `sha256:fd44350b9c9f30a8268e94a94a4efe7eb7ea6fff65327a9a7b5b32aab4c5a2b2` | immutable external run artifact | Complete native execution and observer capture |
| EXP-0027-E002 | `results/report.json`; retained validator reports each 6,306 bytes, `sha256:4f86ef5dfc0959d976c05d3a21f132ec4d3dfb6413d5c2465ad416ded8ab34ad` | canonical checked-in result plus byte-identical Python/Rust artifacts | Semantic interpretation, typed outcomes, and Q1--Q5 |
| EXP-0027-E003 | `results/attacks.json`; retained attack reports each 5,158 bytes, `sha256:2857362729cc88450ca72166ea6ca919d19828bdb947a3c3f26edd89a2dd6a0f` | canonical checked-in result plus byte-identical Python/Rust artifacts | Forty-eight exact adversarial classifications |
| EXP-0027-E004 | `results/execution.json`, 1,444 bytes, `sha256:60a5fdae90d997dbedc3c94c90752801e369dd22ee87bae48a9894f6004b9612` | canonical checked-in result | Final `revise` decision, capture binding, and execution identity `sha256:437064e71406bfcccfd8dd87ea6a58dc6c38adf8bc348b1714d5e5aa85fc9578` |
| EXP-0027-D001 | `CONCLUSION.md` | concluded | Interpretation, limitations, and successor requirements |

The raw capture and 48 mutated captures remain in the retained workflow
artifact. Compact canonical result payloads are checked in; their final newline
is not part of the external artifact sizes or hashes.
