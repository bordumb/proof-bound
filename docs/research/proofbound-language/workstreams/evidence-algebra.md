# WS-EA: evidence algebra

- **Status:** running; initial inventory in EXP-0005; sampling sequence concluded in EXP-0008
- **Hypothesis:** H2
- **Depends on:** WS-IR field classification
- **Blocks:** DSL typing and native evidence constructors

## Objective

Represent evidence strength as closed typed constructors and explicit
derivation rules rather than a common success Boolean.

## Required distinctions

Examples, sampled properties, finite exhaustive checks, bounded model checks,
universal source proofs, source correspondence, artifact correspondence,
reproducibility, mutation witnesses, and human review.

## Exit criteria

Every current derivation has an explicit rule, producer and checker agree over
a generated corpus, and forbidden strengthening is unrepresentable or rejected.

## Stop condition

Do not proceed if compatibility requires flattening sampled, bounded, formal,
or artifact evidence.

## Active experiments

- [EXP-0005](../../../experiments/0005-assurance-ir-extraction/README.md)
  extracts the common algebra and keeps legacy sampling visible.
- [EXP-0006](../../../experiments/0006-explicit-sampling-contract/README.md)
  shows that Hypothesis and fast-check can emit one explicit, independently
  checked sampling contract through an adapter-owned driver, while ordinary
  runner instrumentation cannot. A Rust framework remains the holdout.
- [EXP-0007](../../../experiments/0007-rust-sampling-holdout/README.md)
  falsifies the EXP-0006 shape as one complete execution contract: proptest
  needs a bound RNG algorithm and cannot authoritatively expose the same
  counter set. The next candidate is a layered intent/plan/observation model.
- [EXP-0008](../../../experiments/0008-layered-sampling-model/README.md)
  passes that layered model in independent Rust and Python implementations.
  Common intent and admission stay backend-neutral; typed plans retain backend
  execution controls; unavailable telemetry has a consequence only when a
  registered admission rule consumes it.
