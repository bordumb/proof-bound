# WS-NE: native executable prototype

- **Status:** EXP-LANG-009 specification-falsifier prerequisite active
- **Hypothesis:** H7
- **Depends on:** WS-IR, WS-EA, WS-DSL, WS-FX, WS-IK
- **Blocks:** native-language decision and mixed migration

## Objective

Implement one small deterministic subject—preferably a canonical parser and
serializer—with executable code, specifications, proof obligations, effects,
reproducible artifacts, and portable assurance.

## Active prerequisite

[EXP-LANG-009 / Experiment 0014](../../../experiments/0014-specification-falsifiers/README.md)
tests whether the bounded contract form can reject vacuous, inconsistent, and
mutation-insensitive parser specifications before any native implementation is
allowed to rely on them.

## Exit criteria

At least one universal functional property is independently checkable; examples
and sampled properties remain separately typed; artifact correspondence is
explicit; the result composes with an existing Python or TypeScript claim.

## Stop condition

Stop expansion if the result is no stronger or simpler than integrating a small
Verus, Lean, or Dafny component through existing Proofbound.
