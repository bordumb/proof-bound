# Experiment 0007 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0007-R001 | `README.md` | preregistration at `b2fc6cd`, `sha256:c845f7093a1fcf3b9842e43686a27b21657f481feb48a3b97aedb6a4f530936c` | Human questions, procedure, and decision rule |
| EXP-0007-R002 | `preregistration.json` | preregistration revision 1 at `b2fc6cd`, `sha256:41defe869dfc33eda84b9036e2fc872134549c8dce3dc7199d0175a8e1a241a6` | Machine subjects, parameters, attacks, and decision rule |
| EXP-0007-P001 | `corpus/rust/src/main.rs` | probe at `a30e63d`, `sha256:9936a913d087b77809334ddf21bfaa5e530d0f5824096e3eb2c91f603b2beb98` | Public-API proptest execution and RNG-substitution probe |
| EXP-0007-X001 | `results/2026-09-02-proptest-holdout.json` | immutable falsification result, `sha256:663c984f6a87aaf6e2aa2dced71ea54a87aa19232988f669ca44e6a2486935ae` | Records the RNG collision, counter-authority gaps, stop decision, and layered-design consequence |

Executed results are immutable files under `results/`; bounded fixtures belong
under `corpus/`. Cargo targets and framework caches are never committed.
