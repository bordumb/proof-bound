# WS-IN: dependency and invalidation semantics

- **Status:** planned
- **Hypothesis:** H3
- **Depends on:** WS-IR dependency representation
- **Blocks:** trustworthy incremental language feedback

## Objective

Derive exactly which conclusions lose support when code, tools, permissions,
absence, configuration, assumptions, policies, or external contracts change.

## Method

Turn known cache and closure defects into adversarial fixtures, predict
invalidation from typed dependencies, execute fresh checks, and compare.

## Exit criteria

Zero false retention in the registered corpus, narrow handling of unrelated
changes, and a specific changed-dependency path for every invalidation.
