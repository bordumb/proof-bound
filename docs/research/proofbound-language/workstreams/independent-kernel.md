# WS-IK: independent semantic kernel

- **Status:** bounded `/2` and native differential results supported; production validation open
- **Hypotheses:** H1, H2, H7
- **Active experiment:** EXP-LANG-010 and [EXP-LANG-007 / Experiment 0016](../../../experiments/0016-native-canonical-parser/README.md) concluded; EXP-LANG-008 next
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
