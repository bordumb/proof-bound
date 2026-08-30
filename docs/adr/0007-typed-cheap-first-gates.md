# ADR 0007: Run repository gates through a typed, cheap-first orchestrator

Status: accepted

## Context

The original bootstrap gate encoded orchestration directly in Just and GitHub
Actions shell blocks. Small quoting, formatting, and lint failures could remain
hidden until after costly model-checking work. Shell-owned temporary-directory
lifetime also made the release boundary harder to test consistently.

## Decision

Use `crates/xtask` as the single implementation of the repository development
gate. Just and hosted CI are thin entry points. The runner constructs programs,
argument vectors, environment, phase order, and temporary paths as typed Rust
values; it does not assemble shell command strings.

The order is fail-fast:

1. formatting, linting, workspace and schema tests, and the Lean build;
2. a deterministic proof-free release built through the production serializer
   and checked by the independent verifier;
3. adapter protocol and inventory checks;
4. exactly one full `proofbound check --fresh`, including expensive registered
   proof/model-check units;
5. release construction from that immediately preceding result; and
6. `proofbound-verify` as the final verdict.

The deterministic smoke release is development infrastructure, not assurance
evidence and not a project release. It catches serializer, canonicalization,
and verifier-interface errors before expensive tools run. Focused preflight
unit cases cover policy deduplication and graph/evidence closure in the same
cheap phase boundary.

## Consequences

- `cargo xtask preflight` and `cargo xtask release-smoke` are fast local failure
  boundaries for ordinary mistakes.
- `cargo xtask bootstrap-ci` provides the one honest disposable clean-tree gate
  required before this repository's first implementation commit (ADR 0001).
- The full gate does not rerun Kani merely to construct a release; the release
  consumes the receipts from the one fresh check.
- Process failure reports identify the typed phase and step that failed.
- CI remains verify-only. Regeneration is still confined to the explicit
  `proofbound update` path.
