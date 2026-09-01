# WS-IR: canonical Assurance IR

- **Status:** running
- **Hypotheses:** H1, H2
- **Active experiment:** [EXP-0005](../../../experiments/0005-assurance-ir-extraction/README.md)
- **Depends on:** current manifest, core, release, and verifier semantics
- **Blocks:** every later workstream

## Objective

Extract the smallest versioned representation that preserves current assurance
meaning across existing-language and future native frontends.

## Current work

Inventory revision 2, the 20-case positive corpus, and the non-normative
[Assurance IR `/1` draft](../assurance-ir-v1.md) are complete. Next, register
canonical hash domains and adversarial cases, then implement independent
producer and checker projections without shared decode or derivation code.

## Exit criteria

Selected routes retain exact semantic projections; canonical encoding is
stable; unknown required semantics fail closed; generic derivation has no
concrete backend-name branches.

## Stop condition

Narrow the programme if the IR becomes primarily a union of tool schemas.
