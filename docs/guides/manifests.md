# Manifest guide

The root `proofbound.toml` selects an adoption tier and file patterns for
claims, assumptions, evidence units, translations, model checks, policies, and
reviews. All formats are versioned and reject unknown fields.

Paths are repository-relative. Proofbound rejects absolute paths, `..`,
ambiguous matches, and symlinks at sealed boundaries. Collection and byte
limits apply before parsing. Translation packages, symbols, destinations,
bridges, warnings, and resource budgets belong in manifests; adapters contain
no project-specific lists.

Formal claim identity is a triple: fully qualified declaration,
`lean-expr-cbor/1`, and the domain-separated SHA-256 of its canonical CBOR.
Pretty-printed theorem text is diagnostic only.

See `schemas/` for the public contracts and either demo for complete consumers.

