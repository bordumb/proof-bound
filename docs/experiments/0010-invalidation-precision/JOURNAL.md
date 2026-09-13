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

## 2026-09-03 — Forced-fresh baselines and frozen holdouts

Executed fresh checks from a clean detached worktree at `99f77d5`. All six
Python and all five TypeScript controlled units passed. The Rust mutation,
Cargo test, and Kani units relevant to `DEMO-TRANSFER-003` passed, but its Lean
theorem evidence remained missing despite the doctor reporting the unit
runnable. Thirteen of fourteen registered route shapes therefore have a
passing baseline; the Lean route remains unanswered.

The Click holdout passed its exact existing-test route after its frozen
environment preparation. The Vitest Coverage Report Action holdout failed
closed: Vitest discovered 161 tests while its preregistered instrumentation
named six. The mismatch was not repaired after observation. Both auxiliary
fixtures confirmed their registered facts were load-bearing: changing only
the executable bit of the mode helper failed the Cargo build, and changing the
repository-level transitive source changed the selected package's result.

These executions are retained in `results/forced-fresh-smoke.json`. They do not
constitute the complete forced-fresh change matrix required to pass Q1.

## 2026-09-03 — Revision/read-boundary falsifier and conclusion

Added a real subprocess checker that reads a presentation file absent from its
declared dependency projection. The baseline exits zero and a presentation
change makes the checker exit one. Under the fixed declared projection, the
identity does not change and stale reuse is possible. Under the candidate's
global Git-revision strategy, both the reader and a deliberately unrelated
unit change identity, producing over-invalidation.

The two strategies expose the missing invariant. A dependency list is not
complete merely because it is typed and canonical; the evidence runner must be
prevented from, or accountable for, reading outside that list. The retained
falsifier is `results/revision-falsifier.json`.

Concluded Q1, Q2, Q3, and Q4 as failures and Q5 as a pass. The successful
26-scenario model execution remains evidence about the closed model, not a
claim about arbitrary tool execution. Assurance IR `/1` remains unfrozen, and
the missing effect boundary is promoted to EXP-LANG-005.
