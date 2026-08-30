# ADR 0001: Record unavailable bootstrap-ordering evidence

Status: accepted

## Context

Specification 0001 §20 requires milestone history to demonstrate two temporal
facts: the Tier 0 claim ledger existed before proof work began (M1), and the
framework core was extracted only after project consumers existed (M3). Those
facts are meant to stop Proofbound from retroactively describing an already
built framework as proof-driven dogfood.

The repository's implementation bootstrap did not follow that order. At commit
`90a117e`, only Specification 0001 v0.4.0 was committed. The Tier 0 ledger, both
demos, the framework core, adapters, CLI, and independent verifier were then
built together in one uncommitted working-tree pass. Although individual
subtrees can be made to compile in isolation now, slicing that completed work
into a ledger → demos → core sequence would manufacture historical evidence
for an event that did not occur.

## Decision

Use commit strategy **(b)**: preserve the bootstrap as one honest
implementation pass. Do not reconstruct or stage commits to simulate the §20
dogfood sequence. Before the implementation commit, land only the repository
hygiene ignore rules, and only after the complete `just ci` verify-only gate is
green.

The §20 M1 ledger-before-proofs and M3 consumers-before-extraction acceptance
evidence is therefore **unavailable for this bootstrap**. The bootstrap must not
be cited as satisfying those historical milestone criteria. Current tests,
receipts, and conformance cases establish properties of the resulting tree;
they cannot establish the order in which that tree was created.

The pre-commit gate has one unavoidable bootstrap cycle: `just ci` must pass
before the first implementation commit, while its release stage correctly
requires a clean committed revision. To test that stage without weakening it,
the exact prospective source tree is copied—excluding ignored build and receipt
state—into a disposable, unrelated Git repository. A single ephemeral commit
exists there only long enough to run `just ci`; it is never imported into this
repository and is not milestone or ordering evidence. The real repository then
receives the hygiene-only commit followed by the honest bootstrap commit.
The typed implementation of that procedure is `cargo xtask bootstrap-ci`; it
rejects symlinks and unsafe paths, creates the unrelated one-commit snapshot,
invokes `just ci`, and deletes the snapshot when the process ends.

## Consequences

- README and release language disclose the bootstrap limitation.
- Future dogfood milestones and downstream adopters must produce the required
  ordering in real commit history; this exception is not reusable.
- The implementation can still satisfy the behavioral, schema, and CI gates of
  the specification, but its founding history remains explicitly weaker than
  the process it specifies.
