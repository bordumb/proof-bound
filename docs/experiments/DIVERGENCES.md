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
| EXP-0001-D04 | 0001 | The pinned publish archive omitted a fixture required by four registered `mm-cli` tests. | `bug (fixed at subject commit 878c0a6)` | [ADR 0008](../adr/0008-experiment-0001-fail-closed-dispositions.md) |
| EXP-0001-D05 | 0001 | Q4 requires an explicit producer exclusion in the receipt and simultaneously says the private search must appear in no receipt. | `adr (#8)` | [ADR 0008](../adr/0008-experiment-0001-fail-closed-dispositions.md) |
| EXP-0002-D01 | 0002 | The Auths algebra translation manifest does not own its full invocation or output map; xtask constants remain authoritative. | `adr (#9)` | [ADR 0009](../adr/0009-auths-algebra-pilot-dispositions.md) |
| EXP-0002-D02 | 0002 | Template count checks cover declared files, but hardcoded inventory prevents fail-closed discovery of an undeclared template. | `adr (#9)` | [ADR 0009](../adr/0009-auths-algebra-pilot-dispositions.md) |
| EXP-0002-D03 | 0002 | The legacy `proved`/`qualified` labels collapse Proofbound's theorem, linkage, and assumption facets. | `adr (#9)` | [ADR 0009](../adr/0009-auths-algebra-pilot-dispositions.md) |
| EXP-0002-D04 | 0002 | Auths' package-level Kani source scan admits an extra harness inside a registered package; structured per-harness metadata rejects it. | `adr (#9)` | [ADR 0009](../adr/0009-auths-algebra-pilot-dispositions.md) |
| EXP-0002-D05 | 0002 | The two translated algebra functions have no standalone ledger claims, while the six direct crate claims target a function outside that translation unit. | `adr (#9)` | [ADR 0009](../adr/0009-auths-algebra-pilot-dispositions.md) |
| EXP-0002-D06 | 0002 | Baseline claims 018-020 attribute handwritten Lean `thresholdTwo` theorems to Rust `threshold_counts`. | `adr (#9)` | [ADR 0009](../adr/0009-auths-algebra-pilot-dispositions.md) |
| EXP-0002-D07 | 0002 | Baseline claims 025-027 treat common-origin generated Rust/Lean artifacts as if a Rust linkage were established. | `adr (#9)` | [ADR 0009](../adr/0009-auths-algebra-pilot-dispositions.md) |
| EXP-0002-D08 | 0002 | Auths' rendered-text statement digests are not Proofbound's canonical `lean-expr-cbor/1` identities. | `adr (#9)` | [ADR 0009](../adr/0009-auths-algebra-pilot-dispositions.md) |
| EXP-0002-D09 | 0002 | The qualification runner's Unix device-ID comparison was not portable to macOS, blocking the pinned translation pipeline before execution. | `bug (fixed at subject commit ad4f02c)` | [ADR 0009](../adr/0009-auths-algebra-pilot-dispositions.md) |
| EXP-0003-D01 | 0003 | A root-level Cargo package was converted to the invalid transitive-closure pattern `/**`. | `bug (fixed with regression in experiment 0003 close)` | [ADR 0010](../adr/0010-semver-pilot-boundaries.md) |
| EXP-0003-D02 | 0003 | Charon may exit zero while an inherent-method selector produces an empty translation inventory. | `adr (#10)` | [ADR 0010](../adr/0010-semver-pilot-boundaries.md) |
| EXP-0003-D03 | 0003 | The shipping string/iterator comparator is outside the tested Aeneas subset; the successful pure-kernel extraction measured +180/−4 lines. | `case-record` | [ADR 0010](../adr/0010-semver-pilot-boundaries.md) |
| EXP-0003-D04 | 0003 | The pre-registered phrase “build metadata ignored, total order” is false over concrete versions and must be scoped to a total preorder or quotient/projection order. | `adr (#10)` | [ADR 0010](../adr/0010-semver-pilot-boundaries.md) |
| EXP-0003-D05 | 0003 | Mutation receipts bind registered witnesses and input bytes but v0.5 does not automatically apply the registry's named mutant path. | `accepted-limitation` | [ADR 0010](../adr/0010-semver-pilot-boundaries.md) |
| EXP-0003-D06 | 0003 | A mutation-witness evidence unit spanning multiple mutations invalidates every attached claim when any one witness fails. | `adr (#10)` | [ADR 0010](../adr/0010-semver-pilot-boundaries.md) |
