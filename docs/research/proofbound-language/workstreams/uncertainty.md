# WS-UQ: uncertainty and notification quality

- **Status:** EXP-LANG-006 / Experiment 0013 preregistered
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

The first phase uses a frozen machine oracle to test consequence recall, false
escalation, grouping, completeness, and independent determinism. It cannot
answer whether people respond faster. A separately frozen participant
instrument may run only with enough eligible consenting practitioners; absent
participants leave that question unanswered rather than simulated.

## Active experiment

[EXP-LANG-006 / Experiment 0013](../../../experiments/0013-claim-oriented-notification-precision/README.md)
tests the structural notification candidate and preserves the human-validity
boundary as an explicit question.

## Exit criteria

Lower irrelevant escalation without increasing missed critical consequences;
every notification names an affected claim, dependency path, and requested
decision or action.
