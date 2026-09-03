# WS-UQ: uncertainty and notification quality

- **Status:** bounded machine phase concluded; participant validation pending
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

## Concluded machine experiment

[EXP-LANG-006 / Experiment 0013](../../../experiments/0013-claim-oriented-notification-precision/README.md)
tested the structural notification candidate and preserved the human-validity
boundary as an explicit question. Independent engines agreed exactly, retained
all six critical actions and all 20 findings, and reduced interruptions from
20 to seven with zero candidate false escalation. The participant count was
zero, so the human question remains unanswered.

## Exit criteria

Lower irrelevant escalation without increasing missed critical consequences;
every notification names an affected claim, dependency path, and requested
decision or action.
