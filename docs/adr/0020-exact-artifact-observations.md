# ADR 0020: Exact artifact observations are orthogonal to semantic linkage

- **Status:** Accepted
- **Date:** 2026-09-07
- **Decision owners:** Proofbound maintainers
- **Related:** Specification 0001 sections 3.2, 6.3, and 9.4; ADR 0012;
  Runtime feedback PBF-0008

## Context

Proofbound can currently say either that empirical evidence tested a registered
subject or that an admitted theorem has the exact
`Proofbound.Artifact.DigestBindingV1` root required for `ARTIFACT_BOUND`. It
cannot portably say that a bounded test exercised one exact release artifact
while preserving the claim's `TESTED · MODEL_ONLY` ceiling.

This missing relation matters for native integration tests. A release workflow
can build a binary, execute those exact bytes, and retain the command and result
without proving a universal correspondence between source semantics and the
binary. Treating that observation as `ARTIFACT_BOUND` would be an assurance
upgrade. Omitting the artifact identity would hide a load-bearing fact and
permit substitution between the build and test stages.

The requirement is generic. It is not specific to Runtime, Linux, or a
particular test framework.

## Decision

Proofbound will add a closed **exact artifact observation** evidence family.
It records an empirical procedure applied to exact bytes and produces an
orthogonal observation relation in claim and release receipts. It does not add
a new subject-linkage facet and never derives `ARTIFACT_BOUND`, `REFINED`, or
`PROVED`.

### Formal ceiling

The family is empirical. A passed, policy-admitted observation may contribute
at most `TESTED`. The claim's linkage remains independently derived from
theorem-backed linkage evidence; absent such evidence it remains
`MODEL_ONLY`.

An observation may name one of these closed empirical semantics:

- bounded check;
- independent check;
- exhaustive check;
- property test;
- example test;
- mutation witness; or
- static check.

The selected semantic kind determines the same bounded-domain, mutation,
sampling, and assumption rules as the corresponding existing evidence family.
It is not a caller-authored status.

### Versioned relation

Version 1 of the observation detail records:

- schema identity;
- the exact observed artifact logical name, SHA-256 digest, and byte size;
- a closed logical subject role;
- operating-system and architecture identities;
- the empirical semantic kind and its existing typed family detail;
- the exact observation-procedure artifact identity;
- the toolchain closure identity;
- the complete set of evidence dependencies;
- the evidence record's existing assumptions, premises, commands, results,
  tool identities, source closures, and resource bounds.

Logical roles are stable identifiers, not paths or display labels. Platform
identities use bounded validated strings and cannot be omitted. The observed
artifact and procedure must each occur exactly once in the evidence
provenance's registered input-artifact inventory. The toolchain closure must
occur exactly once in the provenance closure inventory with kind `toolchain`.

Every dependency must be cited by the claim, present in the compiled evidence
catalog, passed, and reachable through a typed `depends-on` graph edge. The
compiler rejects duplicate roles for different bytes within one claim.

### Status and receipt projection

Claim status gains a required, possibly empty, canonically ordered
`artifact_observations` collection. Each entry contains only derived values:
the observation evidence identity, semantic kind, role, artifact, platform,
procedure, toolchain closure, and dependency identities. Producer-authored
linkage and formal facets remain impossible.

The compiled release, portable release receipt, verification report, and
assurance graph preserve the same relation. The relation identity is the
SHA-256 of canonical JSON framed by the fixed domain
`proofbound-exact-artifact-observation/1`.

The independent verifier reconstructs the relation from canonical evidence
records and compares it with the reported relation. Unknown schemas, families,
roles, or fields fail closed.

### Byte availability

An observation is release-verifiable only when the independent verifier can
read the observed bytes and the procedure bytes. Either artifact may be a
sealed member of the release envelope or an explicitly supplied external
artifact. External artifacts are matched by logical role and are hashed by the
verifier; a producer-authored digest alone is insufficient.

The verification report distinguishes:

- `record-consistent`: the typed relation is internally consistent but some
  external bytes were not supplied; and
- `bytes-observed`: every artifact and procedure byte identity was recomputed.

Only `bytes-observed` satisfies an exact-artifact release obligation. Neither
state changes the claim's formal or linkage facet.

### Fail-closed rules

Compilation or independent verification rejects:

- artifact, procedure, role, platform, architecture, or toolchain omission;
- artifact or procedure digest/size disagreement;
- unsupported empirical semantic kinds;
- missing, failed, uncited, or graph-disconnected dependencies;
- inherited assumption, premise, bound, or TCB loss;
- duplicate claim/role relations with different bytes;
- architecture or platform replay;
- relation identity mismatch;
- attempts to use an observation as theorem-backed artifact linkage; and
- attempts to report a stronger formal or linkage facet because an
  observation exists.

### Compatibility

The evidence record, claim-status, compiled-release, release-receipt, and
verification-report schemas advance together. Older compilers and verifiers
reject the new family. New verifiers continue to accept old release schemas
under their old rules but never synthesize observations from untyped
provenance.

## Implementation sequence

Each item is a separate reviewable commit.

1. Freeze this decision and an adversarial conformance inventory.
2. Add the closed core types, validation, canonical relation identity, and
   status projection with unit tests.
3. Add manifest/schema support and adapter derivation from exact registered
   inputs and closures.
4. Add compiled-release and producer receipt projection.
5. Add an independent verifier implementation and external-byte inputs.
6. Run the frozen positive and negative conformance corpus across producer and
   verifier implementations.
7. Adopt the family in Proofbound Runtime's native release workflow without
   promoting any existing facet.

## Consequences

Proofbound can make exact empirical byte observations visible without erasing
the distinction between tests and proofs. Release consumers gain a typed,
independently checked answer to “which bytes did this procedure exercise?”
while `ARTIFACT_BOUND` remains reserved for theorem-derived semantic
correspondence.

The cost is a coordinated schema migration and a verifier interface for
external bytes. Until all implementation steps land, downstream projects must
continue to report the relation as an open release obligation.
