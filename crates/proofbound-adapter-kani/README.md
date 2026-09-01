# Adapter protocol

This executable accepts one canonical JSON `proofbound-adapter-protocol/1`
request on standard input and emits one canonical response on standard output.
The request `unit` is a strict `proofbound-evidence-unit/1` object. Commands
are typed program/argument vectors; manifest strings are never evaluated by a
shell.

Operations are exact. `doctor` runs only the version/capability probe and
returns null evidence with an empty inventory. `inventory` runs Cargo metadata
and fresh Kani metadata discovery, returns the exact nonempty harness inventory,
and returns null evidence because discovery alone is not a bounded check.
`check` and `reproduce` repeat that discovery, then execute the exact registered
harness vector and return a passed observation with the same inventory.
`update` is rejected because Kani owns no committed generated output. Failed
responses always carry null evidence and an empty inventory.

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
the typed reproduction command. For bounded evidence it also copies the exact
ordered assumption strings from the registered model-check unit; those facts
are compiler-owned rather than adapter-authored.
Every run in a passed observation has exit code zero and untruncated output.

The observation is deliberately not a full
`proofbound_core::EvidenceRecord`: a raw adapter unit does not contain the
compiled graph node, whole semantic closure, cache chain, or all claim
premises. The orchestrator validates this observation and adds that provenance
when it constructs the receipt. Failures and unavailable tools return
`success: false`, `evidence: null`, and a stable fail-closed diagnostic.

The registered model-check unit must contain at least one harness. Before
running `cargo kani list`, the adapter requires `kani-list.json` to be absent;
afterward it accepts only the fresh, bounded, regular package-local file. Its
raw `standard-harnesses` JSON object may not repeat a source key; duplicates
are rejected before deserialization can collapse them. The parsed inventory
must be nonempty, duplicate-free, agree with the metadata totals and executable
version, and match the registered harnesses exactly. A zero exit status with no
fresh selection, or a stale/symlinked metadata file, is not bounded-check
evidence.
