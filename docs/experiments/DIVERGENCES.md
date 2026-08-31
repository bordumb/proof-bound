# Divergence ledger

Every experiment finding that forced a change — or a deliberate refusal to
change — lands here. One row per finding, across all experiments. This file
is the Specification 0001 M5 acceptance evidence ("every divergence the pilot
forces is recorded as an abstraction case record or a spec change, not
patched around") in auditable form.

Dispositions: `spec-change (§n, version)` · `adr (#n)` · `case-record` ·
`bug (fixed at <commit>)` · `accepted-limitation`.

| ID | Experiment | Finding | Disposition | Link |
|---|---|---|---|---|
| EXP-0001-D01 | 0001 | Subject-native release verification is substring-based and repository-local, contrary to the structured portable-release contract. | `adr (#8)` | [ADR 0008](../adr/0008-experiment-0001-fail-closed-dispositions.md) |
| EXP-0001-D02 | 0001 | A clean external Proofbound release serialized empty provenance collections differently from the independent verifier's typed canonical form. | `adr (#8)` | [ADR 0008](../adr/0008-experiment-0001-fail-closed-dispositions.md) |
| EXP-0001-D03 | 0001 | Proofbound v0.5 has no manifest/adapter route that emits trusted-transcription evidence with its transcriber and re-encoder TCB nodes. | `adr (#8)` | [ADR 0008](../adr/0008-experiment-0001-fail-closed-dispositions.md) |
| EXP-0001-D04 | 0001 | The pinned publish archive omits a fixture required by four registered `mm-cli` tests. | `adr (#8)` | [ADR 0008](../adr/0008-experiment-0001-fail-closed-dispositions.md) |
| EXP-0001-D05 | 0001 | Q4 requires an explicit producer exclusion in the receipt and simultaneously says the private search must appear in no receipt. | `adr (#8)` | [ADR 0008](../adr/0008-experiment-0001-fail-closed-dispositions.md) |
