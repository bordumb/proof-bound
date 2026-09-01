# Proofbound language research programme

[Research programmes](../README.md) ·
[Language vision](../../notes/proofbound-language.md) ·
[Detailed plan](plan.md)

- **Status:** active
- **Created:** 2026-09-01
- **Last updated:** 2026-09-01
- **Current gate:** Gate 1 — shared semantics
- **Active experiment:** [Experiment 0005 — Assurance IR extraction](../../experiments/0005-assurance-ir-extraction/README.md)
- **Purpose:** Determine whether a small assurance kernel can support existing repositories, a typed assurance DSL, and a native high-assurance language without flattening evidence meaning or expanding into backend-specific exceptions.

## Current position

No language decision has been made. Experiment 0005 is inventorying the
assurance meaning already distributed across manifests, observations, core
records, portable receipts, status derivation, and the independent verifier.
Inventory revision 2 covers registration, observations, core evidence, graph,
policy, assumptions, premises, closures, cache projection, private compiled
state, releases, and derived status. It found a plausible backend-neutral
kernel boundary while retaining typed backend facts at conversion and
invalidation boundaries.

The next bounded tasks are to freeze the positive semantic-projection corpus
and draft Assurance IR `/1`. Neither is an experiment result until independent
projection and adversarial checks execute.

## Programme map

| Document | Authority within research |
|---|---|
| [Hypotheses](hypotheses.md) | Stable hypothesis IDs, claims, falsifiers, and current test state |
| [Roadmap](roadmap.md) | Gate ordering, entry/exit criteria, and strategic decision rules |
| [Corpus](corpus.md) | Registered controlled and external subject inventory |
| [Metrics](metrics.md) | Shared definitions used by several experiments |
| [Open questions](open-questions.md) | Unresolved issues that have not become findings or decisions |
| [Detailed plan](plan.md) | Complete initial methods, workstream rationale, and research backlog |
| [Workstreams](workstreams/README.md) | Bounded programmes of work and their dependencies |

## Workstream dashboard

| ID | Workstream | Status | Hypotheses | Active experiment |
|---|---|---|---|---|
| WS-IR | [Canonical Assurance IR](workstreams/assurance-ir.md) | running | H1, H2 | EXP-0005 |
| WS-EA | [Evidence algebra](workstreams/evidence-algebra.md) | planned | H2 | EXP-0005 initial inventory |
| WS-IN | [Invalidation](workstreams/invalidation.md) | planned | H3 | — |
| WS-DSL | [Typed assurance DSL](workstreams/assurance-dsl.md) | blocked by Gate 1 | H4 | — |
| WS-FX | [Effects and capabilities](workstreams/effects.md) | planned | H5 | — |
| WS-UQ | [Uncertainty and notification quality](workstreams/uncertainty.md) | planned | H6 | — |
| WS-NE | [Native executable prototype](workstreams/native-runtime.md) | blocked by Gate 3 | H7 | — |
| WS-AC | [Artifact correspondence](workstreams/artifact-correspondence.md) | planned | H7 | — |
| WS-FB | [Foreign boundaries](workstreams/foreign-boundaries.md) | blocked by native prototype | H8 | — |
| WS-IK | [Independent kernel](workstreams/independent-kernel.md) | running | H1, H2, H7 | EXP-0005 |

## Current evidence

- The Python and TypeScript implementations show that the assurance model can
  span ecosystems, but they also expose backend-specific pressure in common
  records.
- The standalone verifier demonstrates that producer-independent checking is
  possible for current receipts.
- Experiment 0005 has identified initial classification candidates, including
  Python plugin facts in common provenance and Python-named detail inside a
  cross-language property-test family. Neither is yet a concluded divergence.

## Current decision

Continue Gate 1 only. Do not design final syntax or native executable semantics
until the field inventory, evidence algebra, and invalidation model satisfy
their preregistered criteria.
