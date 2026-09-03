# Proofbound language open questions

[Programme dashboard](README.md)

Open-question IDs are stable. Resolution links to a finding, ADR, or explicit
stop decision; questions are not deleted.

| ID | Question | Related work | Required before |
|---|---|---|---|
| OQ-001 | Can Hypothesis, fast-check, and Rust property-labelled tests share one sampled-property semantic contract without discarding generator, seed, run-budget, and framework meaning? | H1, H2, EXP-0005-F009, EXP-0008 | resolved by layered model |
| OQ-002 | Should backend plugin identities remain common provenance, typed backend detail, or a general capability/dependency record? | H1, H5, EXP-0005 | Assurance IR `/1` and effects prototype |
| OQ-003 | Which claim wording is machine meaning, bounded-domain meaning, and reader presentation? | H1, WS-IR | Claim IR design |
| OQ-004 | Can cache eligibility be derived entirely from typed dependencies rather than maintained as a parallel manually assembled projection? | H3, WS-IN, EXP-LANG-003, EXP-LANG-005 | resolved for mediated operations; opaque processes remain non-reusable |
| OQ-005 | What proof object can an SMT-backed native prototype emit for independent checking without trusting proof search? | H7, WS-NE, WS-IK | Native parser experiment |
| OQ-006 | Which effects can be enforced statically, which require an OS sandbox, and which can only be observed afterward? | H5, H9, WS-FX, EXP-LANG-005, EXP-LANG-011 | bounded macOS project boundary tested; portability and system effects open |
| OQ-007 | How should uncertainty differ from assumptions, exclusions, open obligations, stale evidence, and conflicting evidence? | H6, WS-UQ, EXP-LANG-006 | split structurally; human validation pending |
| OQ-008 | Is a custom DSL materially better than a restricted Pkl or CUE frontend once effective-program review and evaluator identity are included? | H4, WS-DSL, EXP-LANG-004 | split; no frontend selected |

### OQ-001 — split and resolved by a layered contract

- **Date:** 2026-09-02
- **Evidence:** EXP-0006 adapter-owned driver result; EXP-0007 proptest holdout;
  EXP-0008 layered-model result
- **Resolution:** Hypothesis and fast-check can share the EXP-0006 driver
  contract, but proptest falsifies it as a complete three-framework execution
  contract. RNG algorithm is independently configurable under one version and
  seed, while stable typed success/rejection/shrink counters are unavailable.
- **Consequence:** Adopt the split as the research candidate: common intent,
  typed backend execution plan, authority-indexed facts, and a separate
  admission rule. Never infer unavailable counters or add a Rust-only common
  field. Notify only when an unavailable fact is consumed by a registered
  rule.
- **Promoted to:** Assurance IR derivation-trace and migration research

### OQ-004 — split by execution authority

- **Date:** 2026-09-03
- **Evidence:** EXP-LANG-003 model execution and executable revision/read
  falsifier
- **Resolution:** Typed dependencies can derive precise invalidation inside a
  closed model, but declarations alone cannot establish that a subprocess read
  nothing else. A global source revision closes that retention hole only by
  over-invalidating unrelated evidence.
- **Consequence:** Keep typed dependencies as the explanation and identity
  substrate, but require an enforced or independently observed effect boundary
  before treating the projection as complete for cache reuse.
- **Promoted to:** EXP-LANG-005 effect-checked replay

EXP-LANG-005 supplies the required follow-up: under a mediated host, complete
typed effects derive reusable trace identity and preserve narrow invalidation.
An ordinary subprocess does not satisfy that premise and remains non-reusable.

### OQ-006 — split by mediation boundary

- **Date:** 2026-09-03
- **Evidence:** EXP-LANG-005 / Experiment 0012
- **Resolution:** Undeclared and denied capabilities can fail before a
  mediated workload starts; a language host can trace exact file, absence,
  ephemeral-write, secret, and synthetic execution effects. A native process
  is not closed merely because its command is registered. It must remain
  opaque and non-reusable unless a separately identified enforcement layer
  supplies exact evidence.
- **Consequence:** Keep mediated, opaque, and externally enforced execution as
  distinct types. Do not infer sandbox guarantees from command provenance.
- **Promoted to:** EXP-LANG-011 / Experiment 0018, preregistered before any
  production effect-based cache reuse

EXP-LANG-011 supplies bounded external-enforcement evidence: all registered
project, environment, process, network, and write attacks were denied across
three runtimes, with independent receipt agreement. It also exposes the next
split. Exact project authority is feasible on the frozen macOS boundary, while
ancestor metadata and system reads require separately named authority; the
mechanism missed its latency ceiling and has no portable equivalent yet.

### OQ-007 — split between typed semantics and human effect

- **Date:** 2026-09-03
- **Evidence:** EXP-LANG-006 / Experiment 0013
- **Resolution:** The bounded candidate can represent assumption, exclusion,
  uncertainty, contradiction, stale evidence, and missing evidence as six
  disjoint states with typed consequences. Independent engines derive the same
  claim-oriented decisions and reject all registered category coercions. This
  resolves the structural distinction only.
- **Consequence:** Carry the six-state ontology and consumed claim-impact paths
  into the successor language candidate. Do not infer human comprehension,
  response time, or fatigue reduction from the machine volume proxy.
- **Promoted to:** a separately recruited, consented participant experiment
  with the frozen minimum of 12 eligible practitioners

### OQ-008 — split by semantics, provenance, and diagnostics

- **Date:** 2026-09-03
- **Evidence:** EXP-LANG-004 / Experiment 0011
- **Resolution:** Both typed frontends reduced assignments by at least 25% for
  Python and TypeScript, and both independently compiled to the same effective
  meaning as TOML. Neither met the threshold for Rust. Pkl required a bound
  evaluator and authority policy; the custom DSL required a new parser and
  formatter. The experiment cannot choose between them because its frozen
  hashes were invalid and its semantic diagnostics lost source spans.
- **Consequence:** Separate effective-programme identity from frontend
  provenance. Do not demand identical receipts from different frontends, and
  do not select a syntax until source-aware semantic diagnostics and corrected
  controls are tested.
- **Promoted to:** a future confirmatory frontend study after Gate 1

## Resolution format

```markdown
### OQ-NNN — resolved | split | rejected

- Date:
- Evidence:
- Resolution:
- Consequence:
- Promoted to:
```
