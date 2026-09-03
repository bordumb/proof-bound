# WS-IN: dependency and invalidation semantics

- **Status:** running — EXP-LANG-003 preregistered
- **Hypothesis:** H3
- **Depends on:** EXP-0005 cache-dependency falsifier
- **Blocks:** trustworthy incremental language feedback

## Objective

Derive exactly which conclusions lose support when code, tools, permissions,
absence, configuration, assumptions, policies, or external contracts change.

## Active experiment

[EXP-LANG-003 / Experiment 0010](../../../experiments/0010-invalidation-precision/README.md)
tests fifteen controlled units across fourteen route shapes and two external
holdouts. Its registration fixes the dependency constructors, twelve change
classes, fifteen attacks, exact invalidation-set criterion, and forced-fresh
comparison before implementation.

## Method

Turn known cache and closure defects into adversarial fixtures, predict
invalidation from typed dependencies, execute fresh checks, and compare.

EXP-0005 fixes the starting constraint: a cache key and prior receipt are not a
dependency model. EXP-LANG-003 must retain the semantic and execution inputs
that make reuse valid, including typed roles and absence or metadata facts when
they affect execution. It must compare predicted invalidation with fresh
execution and measure irrelevant invalidation separately from false retention.

## Exit criteria

Zero false retention in the registered corpus, narrow handling of unrelated
changes, and a specific changed-dependency path for every invalidation.
