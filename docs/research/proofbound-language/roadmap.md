# Proofbound language research roadmap

[Programme dashboard](README.md) · [Hypotheses](hypotheses.md)

The roadmap is dependency-ordered rather than a calendar commitment.

```text
Gate 0: baseline
    ↓
Gate 1: Assurance IR + evidence algebra + invalidation
    ↓
Gate 2: typed assurance DSL + effects
    ↓
Gate 3: uncertainty and product-value evaluation
    ↓
Gate 4: native executable and artifact feasibility
    ↓
Gate 5: mixed-language adoption and language decision
```

## Gate 0 — Baseline

Required: golden current outputs, evidence-family inventory, trust-boundary
map, known adversarial regressions, and preregistered shared-semantics
experiments.

Status: substantially complete; Experiment 0005 is concluded.

## Gate 1 — Shared semantics

Required: WS-IR, WS-EA, WS-IN, and the independent-kernel portion needed to
check them.

Exit only if:

- the IR is smaller and more stable than the union of backend schemas;
- every status derivation is explicit;
- sampled, bounded, formal, and artifact evidence remain distinct; and
- invalidation has zero known false retention.

Current result: blocked. EXP-LANG-003 rejected declaration-only invalidation;
an enforceable read/effect boundary must be tested before this gate can exit.

## Gate 2 — Authoring and authority

Required: WS-DSL and WS-FX.

Exit only if equivalent frontends emit identical canonical IR, meaningful
errors fail before execution, and effects prevent demonstrated defects without
unacceptable ceremony.

## Gate 3 — Product value

Required: WS-UQ and structured user studies.

Exit only if claim-oriented uncertainty improves impact assessment or reduces
irrelevant escalation without increasing missed critical consequences.

## Gate 4 — Native feasibility

Required: WS-NE and WS-AC.

Exit only if a native prototype produces independently checkable functional
assurance and an honest source-to-artifact story stronger than a comparable
existing-language integration.

## Gate 5 — Adoption bridge

Required: WS-FB plus final WS-IK validation.

Proceed to a language specification only if mixed-language migration is honest
and usable, the independent implementations agree, and existing-language
Proofbound remains a first-class product.

## Strategic outcomes

- **Remain a framework** if no compact cross-ecosystem semantic core survives.
- **Ship an assurance DSL** if typed authoring is valuable but native execution
  adds disproportionate compiler and ecosystem cost.
- **Develop a native language** only if Gate 5 passes.
