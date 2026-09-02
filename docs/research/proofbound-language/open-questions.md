# Proofbound language open questions

[Programme dashboard](README.md)

Open-question IDs are stable. Resolution links to a finding, ADR, or explicit
stop decision; questions are not deleted.

| ID | Question | Related work | Required before |
|---|---|---|---|
| OQ-001 | Can Hypothesis, fast-check, and Rust property-labelled tests share one sampled-property semantic contract without discarding generator, seed, run-budget, and framework meaning? Current captures retain explicit sampling only for Hypothesis. | H1, H2, EXP-0005-F009 | Assurance IR `/1` |
| OQ-002 | Should backend plugin identities remain common provenance, typed backend detail, or a general capability/dependency record? | H1, H5, EXP-0005 | Assurance IR `/1` and effects prototype |
| OQ-003 | Which claim wording is machine meaning, bounded-domain meaning, and reader presentation? | H1, WS-IR | Claim IR design |
| OQ-004 | Can cache eligibility be derived entirely from typed dependencies rather than maintained as a parallel manually assembled projection? | H3, WS-IN | Invalidation experiment |
| OQ-005 | What proof object can an SMT-backed native prototype emit for independent checking without trusting proof search? | H7, WS-NE, WS-IK | Native parser experiment |
| OQ-006 | Which effects can be enforced statically, which require an OS sandbox, and which can only be observed afterward? | H5, WS-FX | Gate 2 |
| OQ-007 | How should uncertainty differ from assumptions, exclusions, open obligations, stale evidence, and conflicting evidence? | H6, WS-UQ | Notification study |
| OQ-008 | Is a custom DSL materially better than a restricted Pkl or CUE frontend once effective-program review and evaluator identity are included? | H4, WS-DSL | Frontend selection |

### OQ-001 — rejected as one exact execution contract

- **Date:** 2026-09-02
- **Evidence:** EXP-0006 adapter-owned driver result; EXP-0007 proptest holdout
- **Resolution:** Hypothesis and fast-check can share the EXP-0006 driver
  contract, but proptest falsifies it as a complete three-framework execution
  contract. RNG algorithm is independently configurable under one version and
  seed, while stable typed success/rejection/shrink counters are unavailable.
- **Consequence:** Keep a common sampled-property semantic family, but split
  common intent from typed backend execution plans and capability-indexed
  observations. Never infer unavailable counters or add a Rust-only common
  field.
- **Promoted to:** layered sampling-model experiment

## Resolution format

```markdown
### OQ-NNN — resolved | split | rejected

- Date:
- Evidence:
- Resolution:
- Consequence:
- Promoted to:
```
