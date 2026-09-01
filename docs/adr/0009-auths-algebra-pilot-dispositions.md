# ADR 0009: Preserve manifest inversion and per-harness identity

Status: accepted

## Context

Experiment 0002 tested the smallest Auths Pattern-B unit. The subject's
qualification manifest records expected results but does not own the complete
Charon/Aeneas invocation. Its quarantine and generated-file inventories are
also cross-checked against Rust constants rather than discovered from an
exclusive output boundary. The legacy assurance ledger uses single status
labels, and its Kani gate counts proof attributes inside registered packages
without declaring each harness identity. The claim inventory also does not
align with the two-function translation unit: some Rust attributions point to
handwritten or common-origin generated Lean, and the legacy statement digest
uses rendered text rather than Proofbound's canonical expression encoding.

Specification 0001 v0.5 already requires the inverse: typed manifests are
authoritative, generated output is exclusive and exhaustively inventoried,
facets remain separate, and Kani inventory comes from tool metadata.

## Decision

- Do not add Auths-specific constants to Proofbound and do not edit Auths
  xtask constants to simulate manifest authority. Q1 remains failed until the
  generic manifest can drive two clean translations.
- Treat undeclared generated/template files as a closure violation. Exact
  counts on a hand-enumerated list are useful but insufficient, so Q2 remains
  failed even though the current algebra output contains no axioms.
- Do not translate `proved` or `qualified` into a stronger aggregate label.
  The eight algebra-linked claims require separate theorem, source-linkage,
  assumption, and policy evidence; absent fresh receipts, Q3 is unanswered.
  Handwritten and common-origin generated Lean remain `MODEL_ONLY` until an
  actual source-refinement theorem is registered, and statement identities
  must be recomputed from `lean-expr-cbor/1` rather than copied.
- Use Kani's structured metadata and exact bidirectional harness sets. A
  protocol response with `success:false` is a failed gate even though the
  adapter process exits normally after returning the diagnostic.
- Repair subject-local portability defects when they prevent the pinned tools
  from running, but do so on the required throwaway branch with checked
  conversions, regression coverage, reviewed closure rebinding, and no remote
  action. Such a repair restores capability; it does not waive or redefine a
  manifest-authority criterion.

## Consequences

Q4 passes without a core fork and provides a concrete replacement for the
subject's attribute grep. Q1/Q2 remain redesign findings already demanded by
the normative specification. Exact Charon/Aeneas capability was subsequently
restored and the native pipeline reproduced, strengthening the evidence for
Q1's architectural failure rather than weakening it. No specification change
is needed.
