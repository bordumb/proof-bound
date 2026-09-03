# Assurance IR `/2` research candidate

[Programme dashboard](README.md) ·
[Differential experiment](../../experiments/0015-assurance-ir-differential-kernel/README.md) ·
[Failed `/1` draft](assurance-ir-v1.md)

- **Status:** bounded research candidate; not a production wire
- **Evidence:** EXP-LANG-010 / Experiment 0015
- **Version rule:** `/2` names this candidate; `/1` remains the failed draft

## Purpose

Assurance IR `/2` is the smallest candidate so far that composes the research
programme's supported semantics rather than treating them as independent
attachments. It makes the following joins explicit:

```text
claim ─ specification adequacy
  │
  ├─ evidence family ─ exact artifacts and correspondence
  │       │
  │       ├─ complete typed dependencies ─ invalidation
  │       └─ declared effects ─ enforcement boundary ─ cache eligibility
  │
  ├─ uncertainty ─ consequence and consumption
  └─ closed derivation ─ formal/linkage/assumption facets ─ admission
```

This candidate repairs the known information gap in `/1`: a producer-owned
cache identity is not a substitute for the typed dependencies and enforcement
conditions that justify reuse. It also incorporates the later evidence
algebra, effect, uncertainty, specification, and artifact-role findings.

## Closed concepts

The finite candidate uses six evidence families:

| Family | Maximum formal facet | Maximum linkage facet |
|---|---|---|
| sampled property | tested | model-only |
| bounded check | tested | model-only |
| theorem | proved | model-only |
| mutation witness | tested | model-only |
| trusted transcription | open | transcribed |
| artifact binding | proved | artifact-bound |

The family is assurance semantics, not a backend name. A Python property and a
TypeScript property may compile to the same family while retaining different
tool dependencies and frontend receipts. The common kernel has no pytest,
Vitest, Kani, Lean, Verus, Aeneas, npm, or Cargo branch.

Dependencies have the roles `semantic-source`, `execution-input`, `tool`,
`environment`, `absence`, and `external-contract`. Every evidence record binds
the exact dependency set it consumed. Each dependency states whether it was
declared and observed. This is still a finite research representation; a real
runtime must enforce or observe those claims rather than trust Boolean fields.

Effects name capabilities independently from their boundary:

- `statically-denied`: the workload cannot request the authority;
- `mediated`: a typed host observes and constrains the operation;
- `externally-enforced`: a separately identified enforcement contract applies;
- `opaque`: the subprocess may exercise ambient authority and is not reusable.

Every effect has an observed or unused disposition. Only external enforcement
may reference an enforcement dependency. An opaque effect deterministically
removes cache eligibility.

Artifacts retain `source`, `generated`, `bound`, `sealed`, and `reproduced`
roles. A bound artifact points to the generated artifact it corresponds to. A
reproduced artifact points to the source and must have identical bytes and
size. Family rules require exact role sets rather than accepting a same-count
substitution.

Specifications carry separate suite and adequacy identities. The frozen
candidate requires reachable canonicality, consumption, malformed-rejection,
round-trip, and termination roles, plus complete results for six named
semantic mutants. The kernel does not infer that these checks establish
general specification completeness.

Uncertainty distinguishes `assumption`, `exclusion`, `open-obligation`,
`stale-evidence`, `conflicting-evidence`, and `unavailable-telemetry`.
Consequences are typed: mark the claim assumed, block admission, or remain
informational. Load-bearing uncertainty must be consumed by the decision;
unused telemetry must not become a generic warning or premise.

## Derived outputs

No input status is authoritative. The kernel derives:

- a semantic programme identity;
- an exact dependency-projection identity;
- the evidence invalidated by a changed dependency;
- a four-step derivation identity;
- formal, linkage, and assumption facets;
- admission and cache eligibility; and
- the exact uncertainty records consumed by the decision.

The four closed derivation rules validate evidence, select the family ceiling,
evaluate uncertainty, and decide admission. Each rule consumes exact record or
prior-step identities. The root and trace identity are recomputed.

## Differential evidence

Experiment 0015 expanded six profiles into 500 valid and 500 single-mutation
programmes. Independently written Rust and Python kernels produced identical
complete model reports over ten repetitions. They rejected all 28 registered
schema, join, effect, specification, artifact, uncertainty, derivation,
invalidation, cache, and strengthening attacks with exact codes.

The Rust kernel is 1,576 measured nonblank non-comment lines and the Python
kernel 855. The canonical model report is 10,241 bytes and the generated corpus
4,701,210 bytes. Neither kernel has a direct adapter, CLI, production core, or
standalone-verifier dependency, and neither source contains a forbidden
backend name.

These results support `/2` as the bounded semantic target for the first native
prototype. They do not prove either kernel, validate real effect enforcement,
cover every production evidence route, establish source syntax, or authorize a
production wire migration.

## Required successor work

EXP-LANG-007 must compile and execute one native parser against this semantic
target while preserving the finite specification suite from EXP-LANG-009.
EXP-LANG-008 must then test whether a foreign caller can join the same graph
without turning correspondence into proof. Production adoption remains gated
on those results and a wider route-parity audit.
