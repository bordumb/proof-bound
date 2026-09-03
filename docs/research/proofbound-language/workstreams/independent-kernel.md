# WS-IK: independent semantic kernel

- **Status:** bounded EXP-0005/0009/0010 results; effect-boundary revision pending
- **Hypotheses:** H1, H2, H7
- **Active experiment:** EXP-LANG-004 is next; [EXP-LANG-003](../../../experiments/0010-invalidation-precision/README.md) is concluded
- **Depends on:** canonical IR and evidence algebra
- **Blocks:** every strong portable language claim

## Objective

Keep final validation, derivation, and publication checking small,
backend-independent, and separately implemented from rich frontends and proof
search.

## Method

Track code and dependencies, maintain differential corpora, mutation-test joins
and canonicalization, and mechanize the highest-impact inference rules.

## Exit criteria

No adapter dependency enters the checker, independent implementations agree,
every strong status has a derivation trace, and unknown or ambiguous semantics
fail closed within a preregistered complexity budget.
