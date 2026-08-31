# Adapter protocol

This executable accepts one canonical JSON `proofbound-adapter-protocol/1`
request on standard input and emits one canonical response on standard output.
The request `unit` is a strict `proofbound-evidence-unit/1` object. Commands
are typed program/argument vectors; manifest strings are never evaluated by a
shell.

For Charon/Aeneas translation, the referenced
`proofbound-translation-unit/3` manifest is the execution plan. Its ordered
invocations provide every Cargo manifest, package/crate identity, LLBC path,
symbol list, optional Aeneas subdirectory, and produced-to-destination output
mapping. The adapter does not discover package or output layout. It rejects
missing and undeclared generated files, resolves every external bridge module
through exactly one declared external source root, and compares committed
Lean and report artifacts as raw bytes. Only the pretty-printed LLBC
projection is normalized for the two-run determinism check.

Every `produced` path is relative to the invocation's Aeneas `-dest` root.
When `aeneas_subdir` is set, Lean-source mappings include that prefix while
the report remains exactly `translation.json` at the destination root. Every
`start_from` root must resolve to a supported, non-opaque local function or
type. Independently, the report's complete supported-local function/type
closure (including transitive dependencies) must be nonempty and exactly equal
to the invocation's typed `translated_closure` rows; a successful process exit
is never enough. Missing, extra, duplicate, cross-kind, external, opaque,
unsupported, and ambiguous roots or closure entries fail closed. Evidence
inventory uses globally sorted `function:<rust-name>` / `type:<rust-name>`
entries; selector order remains separately manifest-bound.
The pinned report shape is closed. Nonempty global, trait-declaration, or
trait-implementation categories currently fail as unsupported instead of
being silently omitted from evidence.

`update` runs inside the orchestrator's sealed checkout, replaces only the
complete declared generated tree, and returns no evidence. The orchestrator
alone imports those reviewed output changes into the working tree.

Successful evidence-producing operations return a common observation in the
response's `evidence` field. All non-Lean adapters use this exact
`proofbound-adapter-observation/2` shape:

- `unit_id`, `evidence_kind`, and `outcome`;
- `input_artifacts` and `generated_artifacts`, each with logical name,
  SHA-256 identity, and byte size;
- `tool` and `adapter` identities;
- typed `commands` and per-command `runs`;
- start/completion timestamps, normalized result identity, and unit
  configuration identity;
- declared `resource_budget`, measured `resource_usage`, exact `inventory`,
  and normalization profile.

A run records its command index, exit code, raw stdout/stderr identities,
normalized output identity, truncation state, and duration. Environment values
are never emitted; only names, secret classification, and optional
domain-separated value hashes are recorded. `peak_memory_bytes: null` means
the portable adapter process could not measure process-tree RSS and does not
fabricate a zero.

`commands` and `runs` are complete ordered arrays of equal length; run `i`
has `command_index = i`. The compiler preserves the sequence and required
normalization identifier in version-2 evidence provenance and separately adds
the typed reproduction command.

The observation is deliberately not a full
`proofbound_core::EvidenceRecord`: a raw adapter unit does not contain the
compiled graph node, whole semantic closure, cache chain, or all claim
premises. The orchestrator validates this observation and adds that provenance
when it constructs the receipt. Failures and unavailable tools return
`success: false`, `evidence: null`, and a stable fail-closed diagnostic.
