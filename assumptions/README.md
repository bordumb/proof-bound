# Assumption ledger

Proofbound's own current claims have no adopted project assumptions. Their
remaining uncertainty is recorded as open obligations or exclusions in the
claim manifests. Demo-specific assumptions live beside their demos and are
never hidden under a generic “trusted” label.

Representation premises are undischarged by default. A premise may set
`status = "discharged"` only when the same manifest contains a typed
`discharge` naming a separate theorem evidence unit and a scope that covers its
typed `premise_scope`. Proofbound validates the bidirectional claim citations,
rejects circular discharge theorems, and compiles the declaration into a
first-class `discharged-by` graph edge. The status engine and independent
verifier then independently require the theorem to be policy-admitted.
