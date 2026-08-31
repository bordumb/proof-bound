# Test, Python checker, and trusted-transcription adapter

The executable serves five strict adapter identities:

- `rust-test` with a typed `cargo-test` operation;
- `python-test` with a typed `pytest` operation;
- `canonical-artifact` with a typed `artifact-check` operation; and
- `independent-check` with a typed `independent-check` operation; and
- `trusted-transcription` with a typed `transcription` operation.

Python checker operations require a repository-relative, non-symlink `.py`
checker and a non-empty exact `expected_inventory`. The checker and every
registered argument path must also appear verbatim in `inputs`, which binds all
executed bytes into the observation. The adapter invokes resolved `python3`
directly with the checker followed by exactly those registered arguments. It
does not use a shell, accept command strings, follow paths outside the shadow
checkout, or permit committed outputs.

Trusted transcription is the deliberately weaker `external-round-trip`
binding. Its version-2 evidence unit registers exactly a source file, a
committed transcription, and a Python driver. The adapter invokes that driver
with only the fixed `proofbound-transcription-driver/1` ABI:

```text
python3 DRIVER transcribe --source SOURCE --output CANDIDATE
python3 DRIVER reencode --transcription CANDIDATE --output REENCODED
```

Both calls run in a disposable shadow. The candidate must byte-match the
committed transcription and the re-encoded bytes must byte-match the source.
The `inventory`, `check`, and `reproduce` operations all run this connected
round trip, so an inventory response is backed by the same exact observations
rather than by driver exit status alone.
Missing, extra, partial, trailing, symlinked, or out-of-boundary output fails
closed. The nested observation reports only the four observed byte identities,
the exact driver identity, registered formats, and two domain-separated tool
role identities. It has no field for a driver-authored pass bit or TCB node.
The unit's environment allowlist is exactly `["PATH"]`: this is the sole
capability needed to resolve the pinned Python executable across the sealed
adapter-process boundary, and its value is hashed into every command
observation. No other ambient variable is admitted.

## Adapter protocol

This executable accepts one canonical JSON `proofbound-adapter-protocol/1`
request on standard input and emits one canonical response on standard output.
The request `unit` is a strict `proofbound-evidence-unit/1` object, except the
typed trusted-transcription route, which alone uses
`proofbound-evidence-unit/2`. Commands are typed program/argument vectors;
manifest strings are never evaluated by a shell.

Successful evidence-producing operations return a common observation in the
response's `evidence` field. All non-Lean adapters use this exact
`proofbound-adapter-observation/1` shape:

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
