# WS-EA: evidence algebra

- **Status:** planned; initial inventory in EXP-0005
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
