# Proofbound v2 conformance preregistration

This directory freezes conformance inputs for schema changes that are accepted
but not yet implemented. A corpus here is a falsifier contract, not evidence
that an implementation passes it.

`exact-artifact-observation-attacks.json` registers the first closed attack
inventory for ADR 0020. Producer and independent-verifier implementations must
reject every mutation with the exact code recorded by the corpus before the
new evidence family may be used by a downstream release.
