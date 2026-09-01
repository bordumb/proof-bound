# Test, Python checker, and trusted-transcription adapter

The executable serves five strict adapter identities:

- `rust-test` with a typed `cargo-test` operation;
- `python-test` with a typed `pytest` operation;
- `canonical-artifact` with a typed `artifact-check` operation;
- `independent-check` with a typed `independent-check` operation; and
- `trusted-transcription` with a typed `transcription` operation.

The protocol operations have fixed response meanings. `doctor` probes the
route's tool and returns null evidence with an empty inventory. `inventory`
performs authoritative discovery and exact registration comparison, then
returns null evidence with the canonical nonempty inventory; discovery is not
assurance. `check` and `reproduce` perform the route's full action and return a
passed observation with the same exact inventory. Only generator `update` is
supported; it returns no evidence, and every other route rejects update.
Failures return null evidence and an empty inventory.

Python checker operations require a repository-relative, non-symlink `.py`
checker and a non-empty exact `expected_inventory`. The checker and every
registered argument path must also appear verbatim in `inputs`, which binds all
executed bytes into the observation. The adapter invokes resolved `python3`
directly with the checker followed by exactly those registered arguments. It
does not use a shell, accept command strings, follow paths outside the shadow
checkout, or permit committed outputs.

Independent checkers must emit exactly one compact canonical result and no
trailing bytes:

```json
{"accepted":true,"inventory":["registered-item"],"schema":"proofbound-independent-check-result/1"}
```

The result has no defaulted or extension fields. `accepted` must be true and
the reported inventory must be nonempty, duplicate-free, and exactly equal to
the unit's registered inventory. `inventory`, `check`, and `reproduce` all run
and parse the checker; the inventory response discards the resulting process
observation, while check and reproduce may admit it. A zero exit status without
the exact result is not evidence.
Canonical artifact checkers likewise run for all three operations and retain
their stricter `proofbound-artifact-check-result/1` byte-identity contract.

Every route rejects an empty registered inventory before starting its tool.
Each item must remain nonempty after Unicode trimming, contain at most 4096
Unicode characters, and contain no Unicode control character.
Cargo/libtest and pytest inventories come from collected nodes, generator
inventories come from observed exact output files, and transcription inventory
comes from the two resolved inputs whose bytes participate in the round trip.
Missing, extra, or duplicate selected items fail closed.
Each registered libtest or pytest node is then invoked alone. The adapter
parses one anchored runner summary proving exactly one pass; substring matches
such as `11 passed` are rejected, and libtest output capture remains enabled so
test-authored stdout cannot impersonate the harness summary.

Mutation witnesses use the separate `proofbound-evidence-unit/3` route and a
singleton `proofbound-mutation-registry/2`. The registry byte-pins one target
preimage, one complete replacement file, and the source file containing one
exact libtest witness. Its mutation ID, affected claims, and four input paths
must exactly equal the evidence unit; legacy registrations that merely name a
mutant function are not executable evidence.

Replay uses two independently copied shadows. The unmodified shadow must
compile, collect the registered inventory, and report exactly one passing
witness. The adapter then copies the registered mutant bytes over only the
registered target in the second shadow, checks the exact postimage, recompiles,
requires the complete collected inventory to remain identical, and runs the
same witness alone. Detection means the anchored libtest result reports
exactly one failure with exit code 101. A compilation error, missing test,
crash, other exit code, truncation, still-passing mutant, path escape, symlink,
digest drift, or change to the reviewed root fails closed. Before any child
process, the adapter snapshots the complete reviewed project tree while
excluding explicit ephemeral tool-output roots such as `target/`. The baseline
shadow and original tree must remain identical; the mutant shadow may differ
at exactly the registered target with exactly the registered postimage. The
observation retains the nonzero run truthfully and binds it through a typed
`expected_failure`; it is never rewritten as a successful child process.

Generator verification never asks a program to inspect outputs that are
already present. The adapter builds a fresh candidate project from the exact
registered non-output inputs, keeps every declared output absent, invokes the
generator with the adapter-owned `--update` switch, and compares the resulting
exact path-to-bytes inventory with the committed outputs. A no-op, missing or
extra output, byte drift, seed mutation, symlink, or path escape fails closed.
Only the explicit `update` operation writes the registered project outputs,
and that operation returns no evidence.

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
round trip, so inventory is derived by the same exact execution rather than by
driver exit status alone, although its response intentionally carries null
evidence.
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
typed trusted-transcription and mutation-replay routes, which use
`proofbound-evidence-unit/2` and `proofbound-evidence-unit/3`, respectively.
Commands are typed program/argument vectors; manifest strings are never
evaluated by a shell.

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
has `command_index = i`. Ordinarily every run in passed evidence exits zero.
A mutation replay has one explicitly indexed expected-failure run whose raw
exit must belong to the registered singleton set `{101}`; every other run,
including the baseline witness and both compilations, must exit zero. The
compiler preserves this sequence and the required normalization identifier in
version-3 evidence provenance and separately adds the typed reproduction
command.

The observation is deliberately not a full
`proofbound_core::EvidenceRecord`: a raw adapter unit does not contain the
compiled graph node, whole semantic closure, cache chain, or all claim
premises. The orchestrator validates this observation and adds that provenance
when it constructs the receipt. Failures and unavailable tools return
`success: false`, `evidence: null`, and a stable fail-closed diagnostic.
