# Experiment 0010 journal

[Experiment registration](README.md)

Append-only execution notes begin after the preregistration commit. Corrections
are new entries rather than edits to earlier observations.

## 2026-09-03 — Corpus and ground truth frozen

After preregistration commit `26f460f`, froze fifteen controlled units spanning
all fourteen registered route shapes, two external holdouts, and a minimal
Cargo permission fixture. Every controlled unit names its source manifest and
exact digest. The external cases retain their upstream revision, local project
and unit manifest identities, and generated semantic-closure identity.

The scenario corpus fixes twenty-five evaluation scopes and exact affected-unit
sets before validator implementation. It covers all twelve change classes,
including three presentation controls, an unrelated-language control,
negative module resolution, same-byte executable permission drift, and tool
and environment identities. No result has been observed and no question is
decided by this capture.

## 2026-09-03 — Transitive-source corpus correction

Before implementation, found that revision 1 labelled `decision.rs` transitive
because it was omitted from the evidence manifest, even though it remains
inside the selected Cargo package. The registered change class explicitly says
outside the immediate package. Corpus extension revision 2 therefore adds a
workspace member that imports a root-level `shared.rs` through `#[path]` and
freezes `INV-SC-026` with only that unit affected. Revision 1 remains unchanged;
the effective corpus contains 26 scenarios.

## 2026-09-03 — Typed scenario selectors frozen

Before validator implementation, added a separate revision-3 binding from each
scenario ID to one typed, stable changed-node selector. This closes an
evaluation ambiguity: implementations must derive dependency uses from source
manifests and route contracts, then look up affected units by selector. They
may not parse prose or use the expected affected set to manufacture a passing
projection.

## 2026-09-03 — Candidate model execution

Implemented the versioned dependency projection and invalidation trace in Rust
and in an independently written Python module. Both implementations reject all
fifteen registered attacks with the exact registered codes. An exact shared
canonical vector also produces the same projection and trace identities.

The source converter then read the fifteen controlled manifests, both pinned
external holdouts, and two auxiliary fixtures. It derived nineteen projections
without consulting registered affected sets. Generic invalidation matched all
twenty-six scenario sets exactly: 57 affected-unit events, zero stale-retention
events, zero over-invalidating scenarios, and 57/57 explanation coverage. Rust
independently decoded the retained Python-produced report, recomputed every
trace and metric, and accepted its canonical bytes.

This is only the model-level stage. It does not yet establish Q1's required
forced-fresh agreement or that current cache behavior retains these facts.
