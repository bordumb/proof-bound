# ADR 0012: Derive artifact binding from elaborated theorem content

**Status:** Accepted

**Date:** 2026-08-31

## Context

Experiment 0004 showed that an artifact checker could emit six successful
binding booleans while the cited theorem did not mention the artifact digest.
The compiler copied those booleans into evidence, and both status engines then
awarded `ARTIFACT_BOUND`. Matching the theorem's name was not a semantic
binding. This was a security boundary failure, not a reporting defect.

The standalone verifier previously received only the theorem statement hash.
It could not inspect the elaborated statement and therefore could not repair
the failure independently.

## Decision

Proofbound 0.7 introduces the exact Lean proposition head
`Proofbound.Artifact.DigestBindingV1`. Its first four arguments are literal
claim ID, artifact schema, artifact logical name, and canonical SHA-256
identity; the remaining arguments are the artifact bytes and their meaning.
The proposition itself requires both the digest equality and the meaning of
those same bytes.

An artifact linkage is admitted only when all of the following hold:

1. the attributed, policy-admitted theorem carries its complete canonical
   `lean-expr-cbor/1` statement in the receipt;
2. the receipt's statement hash recomputes from that wire form;
3. the statement's exact outermost application is
   `Proofbound.Artifact.DigestBindingV1` with six arguments and four direct
   canonical string literals;
4. the literal claim ID matches the attributed and evaluated claim;
5. the literal artifact logical name and digest match exactly one checked
   artifact input, whose complete portable identity also includes its byte
   size; and
6. the artifact record points to that exact theorem evidence record.

Neither implementation unfolds aliases, searches nested expressions, nor
trusts a precomputed binding projection. Core and `proofbound-verify`
independently parse the statement wire and derive the same join.

The canonical-artifact checker report is intentionally narrower. It reports
only success, exact inventory, and the adapter-recomputed artifact identity.
It cannot name a theorem, name claims, or assert semantic linkage booleans.
Canonical parsing, re-encoding, and trailing-byte rejection remain work the
registered checker must perform before it succeeds, but its success cannot
manufacture theorem content.

This security fix introduces the explicitly provisional
`proofbound-evidence/2-binding-preview`,
`proofbound-compiled-release/2-binding-preview`, and
`proofbound-release-envelope/2-binding-preview` identities. Version 1
artifact-bound receipts are revoked: they do not contain enough information
for an independent verifier to derive the binding. The final receipt `/2` is
introduced with the remaining fidelity fields in the next separately
reviewable change; the preview identity is never silently redefined.

`bytes-in-theorem` remains in the closed vocabulary for historical diagnosis,
but does not confer `ARTIFACT_BOUND` in 0.7 until it has an equally exact typed
statement form and portable byte comparison. `trusted-transcription` remains
the honest weaker classification for external transcription.

## Consequences

- Artifact-bound public theorem statements and their statement identities
  change deliberately.
- The artifact demo records native SHA-256 evaluation as an explicit premise;
  native execution is not relabeled as kernel checking.
- A checker can still be defective about its file format, but it cannot bind
  an unrelated theorem by writing `true` into JSON.
- Releases are larger because theorem evidence carries the full elaborated
  expression. That is the information the independent verifier needs to
  enforce the security property.
- Cross-implementation regressions include unrelated-theorem smuggling,
  nested marker, claim/path/digest mismatch, and statement-wire/hash drift.
