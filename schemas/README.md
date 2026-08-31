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
Successful adapters return either a complete `proofbound-evidence/2-binding-preview` record or
the strict, tool-neutral `proofbound-adapter-observation/1` object defined by
`adapter-observation.schema.json`; the compiler validates and converts the
latter without trusting adapter-supplied claim status.

`mutation-registry.schema.json` and
`translation-toolchain-lock.schema.json` are the closed public contracts for
the auxiliary TOML files consumed by the test and Charon/Aeneas adapters.
Schema validation covers their strict shape; adapters additionally enforce
cross-entry uniqueness, concrete tool revisions, and repository bindings.

`error.schema.json` defines the stable `proofbound-error/1` failure envelope
used by JSON-capable CLI commands. Non-applicable contextual fields are
explicitly `null` or empty; they are never silently omitted.

`tcb.schema.json` defines the `proofbound-tcb-ledger/1` projection shipped in a
release. Its component set is recomputed independently from evidence tool and
adapter identities; it is not an unaudited descriptive inventory.
