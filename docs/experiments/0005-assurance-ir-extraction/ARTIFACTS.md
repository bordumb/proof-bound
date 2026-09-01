# Experiment 0005 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0005-A001 | `semantic-field-inventory.md` | frozen, revision 2, `sha256:c3238ccbbf72336157511aaa42defd9894d1846402c9d87f344fd9333e1d404c` | Human-readable classification and boundary analysis |
| EXP-0005-A002 | `field-inventory.json` | frozen, revision 2, `sha256:b47b151ea98020131dc340aca412d437efc3fba9ad3b8605d8dec8affa4f8847` | Machine-readable field classification and backend-branch audit |
| EXP-0005-A003 | `corpus/README.md` | frozen, revision 1, `sha256:c6885f6bf65f94395dbf9350f4e12e367ae873d436ddd783febc58f183f74001` | Human-readable positive corpus contract and coverage |
| EXP-0005-A004 | `results/README.md` | scaffold | Naming and immutability contract for machine-readable run results |
| EXP-0005-A005 | `corpus/cases.json` | frozen, revision 1, `sha256:370c45f5a7a5a492c7c12218ee53be782cd6e8610a70297bd94488801dba5f32` | Twenty exact positive registration, semantic-status, and portable-release cases |
| EXP-0005-A006 | `../../research/proofbound-language/assurance-ir-v1.md` | research draft, `sha256:f409be37930a6203eedbd3146ae256fdbf376cba8677d7e1367b8b98159844b0` | Non-normative Assurance IR `/1` model and falsification boundary |
| EXP-0005-A007 | `corpus/adversarial-cases.json` | preregistered, corrected before execution, revision 2, `sha256:44b99393023f81f7100e9fe7d415d840ed8c439f09597baeb49e539bfbf72f24` | Twenty exact mutations and fail-closed expected results; IR-ADV-003 correction recorded in the journal |
| EXP-0005-A008 | `corpus/canonical-vectors.json` | preregistered, revision 1, `sha256:99ba336f3da82baff8e48c9e4d4116d2d3a878e1e1d6b52f603f3d0c6f225a23` | Canonical JSON contract, five new domains, and 15 expected hashes |
| EXP-0005-A009 | `results/2026-09-01-initial-projection-parity.json` | immutable result, `sha256:29a272074ebd379f6db3c9c243e19b4dbd2eb5f59d26534a69bd7f1b75a6da67` | Rust/Python agreement on 20 positive projections and 15 canonical vectors |

Content digests identify frozen research inputs. Revisions must receive a new
artifact digest; existing frozen bytes are not edited in place after an
executed comparison cites them.
