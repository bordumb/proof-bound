# ADR 0003: Name the Tier 0 adoption policy `ledger`

Status: accepted into Specification 0001 v0.5.0

Specification 0001 requires Tier 0 projects to reach a useful green ledger but
names only theorem, artifact, refinement, native, and bounded trust profiles.
Those profiles all require evidence unavailable at Tier 0.

The implementation therefore reserves `ledger` as an immutable built-in
adoption profile with no formal-evidence requirement. It admits honest
`TESTED`, `ASSUMED`, and `OPEN` facets without changing any stronger
trust-profile meaning. Specification 0001 v0.5.0 §9.1 now makes that behavior
normative. It is not presented as a proof profile, and stronger evidence
remains visible but is not promoted unless the claim selects an appropriate
stronger profile.
