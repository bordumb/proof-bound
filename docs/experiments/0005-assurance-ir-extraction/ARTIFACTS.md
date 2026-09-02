# Experiment 0005 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0005-A001 | `semantic-field-inventory.md` | frozen, revision 2, `sha256:c3238ccbbf72336157511aaa42defd9894d1846402c9d87f344fd9333e1d404c` | Human-readable classification and boundary analysis |
| EXP-0005-A002 | `field-inventory.json` | frozen, revision 2, `sha256:b47b151ea98020131dc340aca412d437efc3fba9ad3b8605d8dec8affa4f8847` | Machine-readable field classification and backend-branch audit |
| EXP-0005-A003 | `corpus/README.md` | frozen positive revision 2 and adversarial revision 2 contract, `sha256:ccc4e8600b1445eedc4863350fc5e7d06a6ac49c31ee524eee17096b8a51d18b` | Human-readable corpus contract, coverage, and pre-execution correction |
| EXP-0005-A004 | `results/README.md` | scaffold | Naming and immutability contract for machine-readable run results |
| EXP-0005-A005 | `corpus/cases.json` | frozen, revision 2, `sha256:508eaa75718a4f4bf221bbec9c4405772a8107689ae7350dfb760f832940a51b` | Twenty exact positive cases, with claim-manifest sources added for Q1; earlier result files remain bound to revision 1 |
| EXP-0005-A006 | `../../research/proofbound-language/assurance-ir-v1.md` | research draft, `sha256:f409be37930a6203eedbd3146ae256fdbf376cba8677d7e1367b8b98159844b0` | Non-normative Assurance IR `/1` model and falsification boundary |
| EXP-0005-A007 | `corpus/adversarial-cases.json` | preregistered, corrected before execution, revision 2, `sha256:44b99393023f81f7100e9fe7d415d840ed8c439f09597baeb49e539bfbf72f24` | Twenty exact mutations and fail-closed expected results; IR-ADV-003 correction recorded in the journal |
| EXP-0005-A008 | `corpus/canonical-vectors.json` | preregistered, revision 1, `sha256:99ba336f3da82baff8e48c9e4d4116d2d3a878e1e1d6b52f603f3d0c6f225a23` | Canonical JSON contract, five new domains, and 15 expected hashes |
| EXP-0005-A009 | `results/2026-09-01-initial-projection-parity.json` | immutable result, `sha256:29a272074ebd379f6db3c9c243e19b4dbd2eb5f59d26534a69bd7f1b75a6da67` | Rust/Python agreement on 20 positive projections and 15 canonical vectors |
| EXP-0005-A010 | `results/2026-09-02-adversarial-evidence-algebra.json` | immutable result, `sha256:36a312a1366fb7075532daea8b97d4fdd60f5bbe1c63b6c3d9874415cdb268fa` | Rust/Python agreement on 20 positives, 20 exact adversarial rejections, 15 canonical vectors, and bounded Q2-Q4 outcomes |
| EXP-0005-A011 | `q1-losslessness-matrix.json` | frozen gap audit, revision 1, `sha256:0cde656cc329800792d6ace3eaf5a8a6b43b51f8a8029052352195f7b38e399b` | Sixteen-row Q1 accounting matrix; one row forward-complete and zero reverse-complete at implementation `f577a55` |
| EXP-0005-A012 | `results/2026-09-02-q1-forward-projection-progress.json` | immutable progress result, `sha256:7d7f57c38137ddd7340c2bffeb5b035d22ea7a0ade4191cb0d50462d61a2ac39`; Q1 remains failed | Rust/Python agreement on 20 expanded programmes, complete portable forward projection for the frozen fixture, and matched omission/join attacks |
| EXP-0005-A013 | `corpus/q1-adversarial-cases.json` | preregistered, revision 1, `sha256:42bfec5a3c792f5516a0a0af93240a154bb0bdc9afb453c3a5a26ce543638133`; not executed | Twelve portable reverse-projection, graph, policy, status, closure, and ledger-join attacks with exact expected codes |

Content digests identify frozen research inputs. Revisions must receive a new
artifact digest; existing frozen bytes are not edited in place after an
executed comparison cites them.
