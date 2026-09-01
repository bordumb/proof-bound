# WS-NE: native executable prototype

- **Status:** blocked by Gate 3
- **Hypothesis:** H7
- **Depends on:** WS-IR, WS-EA, WS-DSL, WS-FX, WS-IK
- **Blocks:** native-language decision and mixed migration

## Objective

Implement one small deterministic subject—preferably a canonical parser and
serializer—with executable code, specifications, proof obligations, effects,
reproducible artifacts, and portable assurance.

## Exit criteria

At least one universal functional property is independently checkable; examples
and sampled properties remain separately typed; artifact correspondence is
explicit; the result composes with an existing Python or TypeScript claim.

## Stop condition

Stop expansion if the result is no stronger or simpler than integrating a small
Verus, Lean, or Dafny component through existing Proofbound.
