# Proofbound v2 conformance preregistration

This directory freezes conformance inputs for schema changes before their
implementation. A corpus begins as a falsifier contract, not evidence that an
implementation passes it; this README records when executable enforcement is
added.

`exact-artifact-observation-attacks.json` registers the first closed attack
inventory for ADR 0020. Producer and independent-verifier implementations must
reject every mutation with the exact code recorded by the corpus before the
new evidence family may be used by a downstream release.

The corpus is now executable. Core evidence validation covers observation
shape and provenance attacks, the producer re-derives cached observations from
the registered manifest before reuse, and the standalone verifier executes all
twelve cases from the frozen JSON inventory, including external byte
substitution, platform replay, assumption loss, status upgrade, and canonical
relation identity substitution.

`evidence-context-attacks.json` preregisters the reviewed activation boundary
for ADR 0021. The corpus is now executable across the manifest, compiler,
release, and independent-verifier boundaries. Every registered mutation is
loaded from the frozen JSON inventory and must produce its exact `PB-CTX-*`
diagnostic; unknown corpus entries fail the tests until an explicit falsifier
is added.

`contextual-artifact-binding-attacks.json` preregisters the closed theorem-set
and reviewed-context boundary for ADR 0022. The corpus is now executable across
the Lean adapter, manifest registration, core status derivation, producer
context selection, release projection, and independent verifier. Every one of
the ten frozen cases must reject with its registered diagnostic, and unknown
corpus entries fail until their falsifier is implemented explicitly.
The implementation review corrected `observation-promotion` from the generic
`PBV_STATUS_MISMATCH` preregistration to `PB-OBS-0011`, the already normative
and more specific diagnostic for an empirical observation attempting to
promote the formal or linkage facet; the preregistration commit retains the
original hypothesis in history.
