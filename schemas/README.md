# Public schemas

All Proofbound manifests and receipts are closed-world, versioned contracts.
Unknown fields are rejected. Paths are repository-relative and are subject to
additional semantic checks (normalization, containment, symlink rejection,
count limits, and byte limits) that JSON Schema alone cannot express.

Canonical JSON uses recursively lexicographically sorted object keys, UTF-8,
and no insignificant whitespace or trailing bytes. Stored canonical files are
byte-for-byte identical to the payload used with the receipt type's domain
separator.

`lean-expr-v1.cddl` is the canonical CBOR layout for elaborated Lean statement
identity. Pretty-printer output is diagnostic only and is never hashed.

`adapter-protocol.schema.json` defines the canonical subprocess envelope.
Successful adapters return either a complete `proofbound-evidence/3` record or
the strict, tool-neutral `proofbound-adapter-observation/2` object defined by
`adapter-observation.schema.json`; the compiler validates and converts the
latter without trusting adapter-supplied claim status.
Operation responses are exact: successful `doctor` is null evidence plus empty
inventory; successful `inventory` is null evidence plus an exact nonempty
inventory; successful `check` and `reproduce` carry passed evidence plus that
same inventory; and `update` never carries passed evidence. Failed responses
carry null evidence and empty inventory. Runtime validation additionally
requires successful inventories to be strictly sorted lexical sets.

`checker-result.schema.json` defines the two accepted checker-output records
consumed by the canonical-artifact and independent-check routes. Both records
are closed, require `accepted: true`, and carry a nonempty, duplicate-free exact
inventory; the artifact record additionally identifies the checked bytes.
Inventory strings are trim-nonempty, contain at most 4096 Unicode characters,
and contain no Unicode control character. Failure diagnostics are not part of
this ABI because adapters reject a nonzero checker exit before parsing its
output. Adapters also require canonical JSON framing with no trailing bytes and
exact equality with the registered inventory, which JSON Schema cannot express.

Version-3 evidence retains version 2's exact registered bounded-assumption strings,
requires nullable `peak_memory_bytes` (`null` means unmeasured; numeric zero is
a measurement), and requires `execution_kind`. `observed-processes` records
the full nonempty ordered `commands` and aligned `runs`; `compiler-internal`
requires both arrays to be empty and cannot fabricate process provenance. Both
kinds retain their nonblank normalization identifier plus a separate typed
`reproduction_command`. The generic observation always uses the ordered
observed-process shape; the compiler adds model registration, claim, closure,
and reproduction provenance that an adapter does not own. JSON Schema enforces
the closed field shapes, while the implementations enforce cross-field
equality, command/run alignment, and exact registration matches.
A passed observed-process record requires a nonempty inventory and
`output_truncated: false` for every run. Every run normally requires exit code
zero. A version-2 singleton mutation replay is the sole exception: its typed
replay block identifies exactly one later run whose only allowed exit code is
101, after the same witness passed against an exact registered preimage. A
passed compiler-internal record
may have an empty inventory because it has no tool-selected targets or runs;
non-passing records may retain failed run facts and empty/partial inventories
for diagnosis.

`translation-unit.schema.json` defines only
`proofbound-translation-unit/3`. Every invocation registers an exact typed
`translated_closure` of supported non-opaque local functions and types in
addition to its selector roots and exact produced-to-destination map. Version 2
is rejected rather than allowing a successful translator exit with an empty or
partial transitive closure.

The version-3 compiled release retains required internal claim `statement`,
optional reader-facing `public_language`, and required derived status
`public_statement` as distinct values. The final field is recomputed, never
accepted as a replacement for the first.

`mutation-registry.schema.json` defines only
`proofbound-mutation-registry/2`: one subject and one mutation with byte-pinned
target preimage, full-file mutant, and witness source. The corresponding
`proofbound-evidence-unit/3` route admits exactly one registry, mutation ID,
inventory entry, evidence fate, and affected-claim set. Multiple mutations may
not share a unit. `translation-toolchain-lock.schema.json` is the corresponding
closed auxiliary TOML contract consumed by the Charon/Aeneas adapter.
Schema validation covers their strict shape; adapters additionally enforce
cross-entry uniqueness, exact observable native tool identities, and repository
bindings. Charon is probed with `charon version`; Aeneas is probed with
`aeneas -version`. Version-1 lock fields do not attest source commits or build
provenance beyond those native outputs.

`error.schema.json` defines the stable `proofbound-error/1` failure envelope
used by JSON-capable CLI commands. Non-applicable contextual fields are
explicitly `null` or empty; they are never silently omitted.

`tcb.schema.json` defines the `proofbound-tcb-ledger/1` projection shipped in a
release. Its component set is recomputed independently from evidence tool and
adapter identities; it is not an unaudited descriptive inventory.
