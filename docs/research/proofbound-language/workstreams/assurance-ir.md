# WS-IR: canonical Assurance IR

- **Status:** draft `/1` falsified; bounded `/2` research candidate supported
- **Hypotheses:** H1, H2
- **Active experiment:** [EXP-LANG-010 / Experiment 0015](../../../experiments/0015-assurance-ir-differential-kernel/README.md) concluded
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
dependency projection does not. EXP-LANG-003's declaration-only successor was
also rejected: ambient reads permit stale reuse, while a global revision
over-invalidates. Draft `/1` is not frozen; a successor must combine retained
dependencies with the enforceable effect boundary tested by EXP-LANG-005
rather than redefining either result.

[Assurance IR `/2`](../assurance-ir-v2.md) is that bounded successor candidate.
Independent Rust and Python kernels agree across six representative profiles,
500 valid programmes, 500 adversarial programmes, and 28 named attacks. It is
the semantic target for EXP-LANG-007, not a production schema: complete route
parity, real effect enforcement, and native source-to-artifact evidence remain
untested.

## Exit criteria

Selected routes retain exact semantic projections; canonical encoding is
stable; unknown required semantics fail closed; generic derivation has no
concrete backend-name branches.

## Stop condition

Narrow the programme if the IR becomes primarily a union of tool schemas.
