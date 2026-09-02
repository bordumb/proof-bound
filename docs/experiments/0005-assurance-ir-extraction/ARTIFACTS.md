# Experiment 0005 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0005-A001 | `semantic-field-inventory.md` | frozen, revision 2, `sha256:c3238ccbbf72336157511aaa42defd9894d1846402c9d87f344fd9333e1d404c` | Human-readable classification and boundary analysis |
| EXP-0005-A002 | `field-inventory.json` | frozen, revision 2, `sha256:b47b151ea98020131dc340aca412d437efc3fba9ad3b8605d8dec8affa4f8847` | Machine-readable field classification and backend-branch audit |
| EXP-0005-A003 | `corpus/README.md` | frozen positive revision 2 and adversarial revision 2 contract, `sha256:ccc4e8600b1445eedc4863350fc5e7d06a6ac49c31ee524eee17096b8a51d18b` | Human-readable corpus contract, coverage, and pre-execution correction |
| EXP-0005-A004 | `results/README.md` | scaffold | Naming and immutability contract for machine-readable run results |
| EXP-0005-A005 | `corpus/cases.json` | frozen, revision 2, `sha256:508eaa75718a4f4bf221bbec9c4405772a8107689ae7350dfb760f832940a51b` | Twenty exact positive cases, with claim-manifest sources added for Q1; earlier result files remain bound to revision 1 |
| EXP-0005-A006 | `../../research/proofbound-language/assurance-ir-v1.md` | research draft, `sha256:969f2e0ce2a4c0e67787ad0c328be61bf006bf38844d8199f35d2a3c4259d377` | Non-normative Assurance IR `/1` model and falsification boundary; updated to retain the portable family gap exposed by complete verticals without freezing the wire |
| EXP-0005-A007 | `corpus/adversarial-cases.json` | preregistered, corrected before execution, revision 2, `sha256:44b99393023f81f7100e9fe7d415d840ed8c439f09597baeb49e539bfbf72f24` | Twenty exact mutations and fail-closed expected results; IR-ADV-003 correction recorded in the journal |
| EXP-0005-A008 | `corpus/canonical-vectors.json` | preregistered, revision 1, `sha256:99ba336f3da82baff8e48c9e4d4116d2d3a878e1e1d6b52f603f3d0c6f225a23` | Canonical JSON contract, five new domains, and 15 expected hashes |
| EXP-0005-A009 | `results/2026-09-01-initial-projection-parity.json` | immutable result, `sha256:29a272074ebd379f6db3c9c243e19b4dbd2eb5f59d26534a69bd7f1b75a6da67` | Rust/Python agreement on 20 positive projections and 15 canonical vectors |
| EXP-0005-A010 | `results/2026-09-02-adversarial-evidence-algebra.json` | immutable result, `sha256:36a312a1366fb7075532daea8b97d4fdd60f5bbe1c63b6c3d9874415cdb268fa` | Rust/Python agreement on 20 positives, 20 exact adversarial rejections, 15 canonical vectors, and bounded Q2-Q4 outcomes |
| EXP-0005-A011 | `q1-losslessness-matrix.json` | frozen gap audit, revision 1, `sha256:0cde656cc329800792d6ace3eaf5a8a6b43b51f8a8029052352195f7b38e399b` | Sixteen-row Q1 accounting matrix; one row forward-complete and zero reverse-complete at implementation `f577a55` |
| EXP-0005-A012 | `results/2026-09-02-q1-forward-projection-progress.json` | immutable progress result, `sha256:7d7f57c38137ddd7340c2bffeb5b035d22ea7a0ade4191cb0d50462d61a2ac39`; Q1 remains failed | Rust/Python agreement on 20 expanded programmes, complete portable forward projection for the frozen fixture, and matched omission/join attacks |
| EXP-0005-A013 | `corpus/q1-adversarial-cases.json` | preregistered, revision 1, `sha256:42bfec5a3c792f5516a0a0af93240a154bb0bdc9afb453c3a5a26ce543638133`; executed at `fb12290` | Twelve portable reverse-projection, graph, policy, status, closure, and ledger-join attacks with exact expected codes |
| EXP-0005-A014 | `q1-losslessness-matrix-r2.json` | immutable executed gap audit, revision 2, `sha256:cd1d632afd38e4eb2171f216659311921ce8f784f4b545102dbd0d7c67d4941c` | Sixteen-row Q1 re-audit after reverse projection and programme typing; nine rows complete, seven partial, Q1 failed |
| EXP-0005-A015 | `results/2026-09-02-q1-losslessness-decision.json` | immutable result, `sha256:bd3034c0e3bed2b1fd16cba001d79a3016306087f6a500971919a88bf511760c` | Honest Q1 decision over 20 positive cases and twelve matched Rust/Python attacks; IR `/1` not frozen and Go holdout not started |
| EXP-0005-A016 | `q1-losslessness-matrix-r3.json` | immutable post-decision gap audit, revision 3, `sha256:b6538db2f76334506af230e84a0bbc2417b4f740b19398a7bdeae0f2fee90839` | Sixteen-row Q1 re-audit after typed family, subject-closure, and TCB work; twelve rows complete, four partial, Q1 still failed |
| EXP-0005-A017 | `results/2026-09-02-q1-representation-hardening.json` | immutable progress result, `sha256:1f22128eedad6d3d629c70f2bcd1671c3aa11d8df033bcc19a9f15b08f05e8c0` | Rust/Python evidence that three known representation gaps closed without freezing Assurance IR `/1` or beginning the holdout |
| EXP-0005-A018 | `q1-completion-preregistration.json` | preregistered, revision 1, `sha256:0815675e11a73cb0a6e3b76179b9e5d39152135b1f1bbf4a7113f6982862ca50`; not executed | Three complete language verticals plus fixed derivation-trace, artifact-role, and cache-invalidation acceptance rules |
| EXP-0005-A019 | `q1-completion-plan.md` | preregistered protocol, `sha256:ba47b094ed9e9f4b4dd621ffbae1b0bad1d304fcd340a2384e733fe58df85676`; not executed | Human-readable capture, storage, ordering, and stop-condition protocol for closing or falsifying the four remaining Q1 rows |
| EXP-0005-A020 | `captures/q1-completion-r1/index.json` | captured, revision 1, `sha256:54ff0bddf5251b1889e608bed86591600157335b0921f0c99b7584f4fae1c998`; analysis pending | Exact identity index and execution record for three complete language vertical captures; binds the nine retained receipt/envelope/TCB files |
| EXP-0005-A021 | `captures/q1-completion-r1/README.md` | capture contract, `sha256:fb58bd806a3090014282f0493937c66d0281eff1e2cbf87701a6def84420d087` | Explains why the retained semantic subset is not itself a standalone portable release |
| EXP-0005-A022 | `q1-losslessness-matrix-r4.json` | immutable completion-capture gap audit, revision 4, `sha256:068b361e99f68f8d08985d0dba6375cf3f652da58d338f81ff30f2a1496944ea` | Reopens typed portable family detail after full releases expose unsupported review and placeholder conversions; eleven rows complete, five partial |
| EXP-0005-A023 | `results/2026-09-02-q1-completion-capture-audit.json` | immutable gap result, `sha256:fabd22157e49fd3d700a5a5759667bae7c99d78e1ca9c839f2e94ca88f7e2336` | Records three verified captures and the exact unsupported portable conversion probe; Q1 remains failed |

Content digests identify frozen research inputs. Revisions must receive a new
artifact digest; existing frozen bytes are not edited in place after an
executed comparison cites them.
