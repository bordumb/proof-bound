# WS-IR: canonical Assurance IR

- **Status:** draft `/1` concluded with a dependency-completeness falsifier
- **Hypotheses:** H1, H2
- **Active experiment:** [EXP-0005](../../../experiments/0005-assurance-ir-extraction/README.md) concluded; revision depends on EXP-LANG-003
- **Depends on:** current manifest, core, release, and verifier semantics
- **Blocks:** every later workstream

## Objective

Extract the smallest versioned representation that preserves current assurance
meaning across existing-language and future native frontends.

## Current work

Inventory revision 2, the 20-case positive corpus, and the non-normative
[Assurance IR `/1` draft](../assurance-ir-v1.md) are complete. Independent
Rust and Python work closes fifteen of sixteen losslessness rows. The remaining
row is load-bearing: exact cache decisions survive, but their complete typed
dependency projection does not. Draft `/1` is not frozen; a successor must be
informed by EXP-LANG-003 rather than redefining this result.

## Exit criteria

Selected routes retain exact semantic projections; canonical encoding is
stable; unknown required semantics fail closed; generic derivation has no
concrete backend-name branches.

## Stop condition

Narrow the programme if the IR becomes primarily a union of tool schemas.
