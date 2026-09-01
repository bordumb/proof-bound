# WS-UQ: uncertainty and notification quality

- **Status:** planned
- **Hypothesis:** H6
- **Depends on:** claim dependencies and invalidation semantics
- **Blocks:** Gate 3 product-value decision

## Objective

Define assumptions, exclusions, uncertainty, stale evidence, contradictions,
and missing evidence precisely enough to report changes in justified confidence
rather than raw tool alerts.

## Method

Compare tool-oriented alerts with claim-oriented scenarios using developers,
security engineers, release owners, and auditors.

## Exit criteria

Lower irrelevant escalation without increasing missed critical consequences;
every notification names an affected claim, dependency path, and requested
decision or action.
