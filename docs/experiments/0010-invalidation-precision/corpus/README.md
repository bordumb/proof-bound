# Experiment 0010 corpus

The bounded corpus will contain source-retained dependency projections,
before/after change scenarios, and explicit ground-truth invalidation sets for
the fifteen controlled units and two external holdouts registered in
[`preregistration.json`](../preregistration.json).

Revision 1 was frozen after the preregistration commit and before validator
implementation:

- [`cases.json`](cases.json) binds every selected controlled unit manifest,
  both external semantic closures, and an auxiliary executable-mode fixture;
- [`scenarios.json`](scenarios.json) freezes 25 changes and their exact affected
  sets; and
- [`fixtures/mode-project/`](fixtures/mode-project/) makes same-byte permission
  drift observably load-bearing rather than merely hypothetical.

[`extension-r2.json`](extension-r2.json) adds a separate Cargo workspace whose
selected member consumes `shared.rs` from outside its immediate package. It
corrects revision 1's narrower interpretation of “transitive” before any
validator implementation or result. Revision 1 remains immutable.

The controlled subject Git revision binds all registered source bytes and
modes. Each external holdout is bound by upstream revision plus its generated
semantic closure identity and exact local Proofbound manifest identities.
Execution will expand these roots into path-level projections. Dependency
directories, build output, private caches, and executable binaries remain
outside Git; their bounded identities and relevant metadata are retained
instead.
