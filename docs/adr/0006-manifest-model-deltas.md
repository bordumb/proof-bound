# ADR 0006: Make the shipped manifest model normative

Status: accepted

## Context

The bootstrap schemas and strict Rust readers required fields that
Specification 0001 v0.4.0 did not enumerate. Leaving those fields only in code
would make the machine contract and normative prose disagree.

## Decision

Specification 0001 v0.5.0 §11.1 now defines the project-level `tier`, all
manifest collection fields, `demo_registry`, `source.external_evidence`, and
the fail-closed `[limits]` table. Section 11.2 now defines claim-level `tier`,
`open_obligations`, `out_of_scope`, `source_roots`, and every other field
accepted by `schemas/claim.schema.json`, including the optional formal identity
triple, subject closure, primary linkage, premises, and bounded domain.

The JSON schemas remain strict (`additionalProperties: false`). Adding a field
to a parser or schema without changing the normative specification is a
contract error, not an implicit extension mechanism.

## Consequences

- Existing bootstrap manifests are normative rather than undocumented dialects.
- Future manifest changes require a versioned schema and specification update.
- Optional collection fields default to empty; security and resource limits use
  the documented versioned defaults.

