# Proofbound contributor guide

The normative contract is `docs/specs/0001_initial_spec.md`. Preserve its
evidence distinctions: tests are never proofs, bounded checks are never
unbounded theorems, and model theorems are not shipping claims without a
registered binding.

## Boundaries

- Domain semantics stay in demos or project plugins, never in framework core.
- `proofbound check` may write only beneath `.proofbound/`; committed artifacts
  are changed exclusively by `proofbound update`.
- `proofbound-verify` must not depend on any other workspace crate. It is an
  intentionally independent implementation of receipt validation and status
  derivation.
- Manifests are strict and drive adapters. Do not add per-project symbols,
  paths, harness names, or unit counts to adapter source.
- Generated Lean lives only in generator-owned directories. Handwritten bridge
  modules must live outside them and be byte-pinned.

Run `just ci` before submitting a change.

