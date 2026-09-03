# WS-IN: dependency and invalidation semantics

- **Status:** declaration-only candidate rejected; enforced revision preregistered
- **Hypotheses:** H3, H9
- **Depends on:** EXP-0005 cache-dependency falsifier
- **Blocks:** trustworthy incremental language feedback

## Objective

Derive exactly which conclusions lose support when code, tools, permissions,
absence, configuration, assumptions, policies, or external contracts change.

## Concluded experiment

[EXP-LANG-003 / Experiment 0010](../../../experiments/0010-invalidation-precision/README.md)
tested fifteen controlled units across fourteen route shapes and two external
holdouts. Its closed model exactly matched all 26 registered invalidation sets,
but a real subprocess falsifier showed that declared dependencies are not
necessarily the dependencies a tool consumes.

## Method

Turn known cache and closure defects into adversarial fixtures, predict
invalidation from typed dependencies, execute fresh checks, and compare.

EXP-0005 fixes the starting constraint: a cache key and prior receipt are not a
dependency model. EXP-LANG-003 must retain the semantic and execution inputs
that make reuse valid, including typed roles and absence or metadata facts when
they affect execution. It must compare predicted invalidation with fresh
execution and measure irrelevant invalidation separately from false retention.

## Result

The workstream did not meet its exit criteria. Declared-only identity can
retain stale evidence after an undeclared read, while a repository revision
identity invalidates unrelated units and lacks an actionable dependency path.
Q1–Q4 failed and Q5 passed. The next candidate must integrate with the
effect/capability workstream so a runner cannot silently consume authority
outside its registered projection.

That successor is now preregistered as
[EXP-LANG-011 / Experiment 0018](../../../experiments/0018-os-enforced-effects/README.md).
It will retain exact typed dependencies for identity and explanation while a
separately identified operating-system boundary prevents the tested process
from consuming undeclared project authority. The experiment must still prove
that load-bearing changes invalidate and the unrelated negative control does
not.
