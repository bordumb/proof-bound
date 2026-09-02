# Experiment 0006 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0006-R001 | `README.md` | preregistration at `c5c4e25`, `sha256:7aa303ae6d269af3cd015e9eef29cce2af1f572495cb34ca551b710a6f915a48` | Human-readable questions, candidate contract, procedure, and stop rules |
| EXP-0006-R002 | `preregistration.json` | preregistration revision 1 at `c5c4e25`, `sha256:6bcac0a434e48799ce4804095b9c3c92bf211a8436de5d317fbb79103567a385` | Machine-readable subjects, routes, fields, attacks, and decision rules |
| EXP-0006-S001 | `demo/python-inventory-service/tests/test_reservations.py` | frozen subject, `sha256:1620fe9d52072f2753265a7ccabdc6d2ff7ba2a4fc7b3c48b214021f52a7f869` | Application source containing the selected Hypothesis property |
| EXP-0006-S002 | `demo/python-inventory-service/evidence/reservation-property.toml` | frozen registration, `sha256:c3d5b220067293b37d696e853f9e3c69574aa97e38e69275d72815c0683afa79` | Existing Python property evidence registration |
| EXP-0006-S003 | `demo/typescript-codec/src/roundtrip.test.ts` | frozen subject, `sha256:997293b3bbc8a965093ce13a56ba73bdacf72a9d4e49ed56c201c020e937680d` | Application source containing the selected fast-check property |
| EXP-0006-S004 | `demo/typescript-codec/evidence/bounded-roundtrip.toml` | frozen registration, `sha256:ab6fbaffa27f04a2b32d88d8721260eb8fb799fca4354759fa0e31af691aba1b` | Existing TypeScript property evidence registration |

Executed results are immutable files under `results/`; bounded fixtures belong
under `corpus/`. Dependency trees and framework caches are never committed.
