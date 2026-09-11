# ADR 0025: Reviewed Lean theorem identity updates

- **Status:** Proposed
- **Date:** 2026-09-11
- **Decision owners:** Proofbound maintainers
- **Origin:** Proofbound Runtime PBF-0002

## Context

The Lean adapter can independently derive a theorem's declaration, canonical
`lean-expr-cbor/1` statement digest, and transitive axiom inventory. Its update
operation previously returned that observation without changing a file, while
the orchestrator required a nonempty output boundary. Users therefore had to
reproduce an internal digest calculation and edit claim identity pins by hand.

## Proposed decision

`proofbound update UNIT` may prepare a Lean theorem identity change only when
the unit owns exactly one registered claim and declares that claim manifest as
its sole exact output. The orchestrator supplies the unit's configured theorem
declaration as the update anchor, invokes the Lean audit inside the sealed
shadow, and accepts only a drifted observation for the same unit and claim.

The observed identity replaces exactly four claim fields:

- `formal_declaration`;
- `statement_encoding`;
- `statement_sha256`; and
- `foundational_axioms`.

The rewrite preserves every other typed manifest field, validates the complete
shadow project, imports only the declared manifest, and reports that reviewed
path. The update observation never becomes passing evidence. A subsequent
verify-only check must rerun the audit against the new pins before the theorem
can satisfy a claim.

The target declaration must still equal the evidence unit's configured theorem
and appear exactly once in its expected inventory. The adapter continues to
reconcile the complete attributed inventory. For the target only, update mode
observes statement and axiom drift; every neighboring claim remains pinned.
Observed foundational and project axioms must already be admitted by the
claim's policy, and `sorryAx` remains forbidden.

## Compatibility

No manifest or receipt schema changes. Existing verify-only behavior is
unchanged. A Lean unit becomes update-capable by declaring its owning claim
manifest as its one output; units without that boundary fail closed with an
actionable `PB-UPDATE-0006` diagnostic.

## Required falsifiers

- missing, foreign, or multiple output manifests are rejected;
- zero or multiple owned claims are rejected;
- a substituted declaration, omitted target, extra attribution, or drifting
  neighboring claim is rejected;
- an unallowlisted foundational or project axiom is rejected;
- a response for another unit or claim is rejected; and
- any adapter write outside the sole manifest boundary is rejected before
  import.

## Review gate

The implementation is present on the PBF-0002 claim-wave branch. This ADR
remains proposed until a reviewer other than the change author approves the
sealed rewrite, policy checks, and update-then-verify tests.
