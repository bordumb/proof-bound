# Proofbound language research programme

[Research programmes](../README.md) ·
[Language vision](../../notes/proofbound-language.md) ·
[Detailed plan](plan.md)

- **Status:** active
- **Created:** 2026-09-01
- **Last updated:** 2026-09-03
- **Current gate:** Gate 1 — shared semantics
- **Active experiment:** [Experiment 0005 — Assurance IR extraction](../../experiments/0005-assurance-ir-extraction/README.md); [Experiments 0006–0009](../../experiments/README.md) concluded the sampling and generated-algebra sequence
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

The positive semantic-projection corpus is frozen and a non-normative
[Assurance IR `/1` draft](assurance-ir-v1.md) makes the proposed boundary
falsifiable. Independent Rust and Python prototypes agree on the original 20
positive cases and their registered attacks. Three complete Python,
TypeScript, and Rust release captures then falsified the earlier generality:
the current converter does not cover all portable family constructors, and
the TypeScript and Rust property receipts do not retain an explicit sampling
contract. Eleven of sixteen Q1 rows are complete; five remain partial.

## Programme map

| Document | Authority within research |
|---|---|
| [Hypotheses](hypotheses.md) | Stable hypothesis IDs, claims, falsifiers, and current test state |
| [Roadmap](roadmap.md) | Gate ordering, entry/exit criteria, and strategic decision rules |
| [Corpus](corpus.md) | Registered controlled and external subject inventory |
| [Metrics](metrics.md) | Shared definitions used by several experiments |
| [Open questions](open-questions.md) | Unresolved issues that have not become findings or decisions |
| [Detailed plan](plan.md) | Complete initial methods, workstream rationale, and research backlog |
| [Draft Assurance IR `/1`](assurance-ir-v1.md) | Non-normative semantic model to test against EXP-0005 |
| [Workstreams](workstreams/README.md) | Bounded programmes of work and their dependencies |

## Workstream dashboard

| ID | Workstream | Status | Hypotheses | Active experiment |
|---|---|---|---|---|
| WS-IR | [Canonical Assurance IR](workstreams/assurance-ir.md) | running | H1, H2 | EXP-0005 |
| WS-EA | [Evidence algebra](workstreams/evidence-algebra.md) | running | H2 | EXP-0005 |
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
  cross-language property-test family.
- Inventory revision 2 and the frozen 20-case corpus now support a concrete IR
  draft. The draft isolates backend conversion and invalidation from common
  validation and derivation.
- The Q1 decision slice adds a portable semantic reverse projection and
  executable Rust/Python agreement on twelve preregistered programme attacks.
- Later representation hardening and complete release captures leave eleven
  of sixteen losslessness rows complete. The capture audit also shows why a
  property label plus an exact source digest is not a typed sampling contract:
  only Python Hypothesis currently retains framework and seed semantics on the
  portable wire.
- A separate closed portable-family projection now covers all 45 captured
  records in Rust and Python, including human review and typed observed detail.
  It deliberately retains the TypeScript and Rust property records as legacy
  sampling and rejects a self-consistently rehashed semantic upgrade.
- Experiment 0006 rejects ordinary-runner and Vitest setup instrumentation,
  then demonstrates one adapter-owned generator/predicate ABI for Hypothesis
  and fast-check. Both independent validators reconstruct the same generator
  and contract identities and reject all ten registered attacks. The result
  resolves the Python/TypeScript part of OQ-001 without upgrading old receipts;
  Rust sampling remains the holdout.
- Experiment 0007 then falsifies the EXP-0006 shape as one exact
  three-framework execution contract. Proptest exposes an independently
  configurable RNG algorithm absent from the common contract, while its
  stable typed API does not expose the required success, rejection, and
  accepted-shrink counters. The evidence supports a layered sampling model,
  not a framework-named kernel branch.
- Experiment 0008 validates that layered candidate over the same frozen
  Hypothesis, fast-check, and proptest sources in independent Rust and Python
  implementations. All twelve attacks match preregistration. In particular,
  a missing completed-budget fact blocks the consuming empirical-admission
  rule, while unavailable shrink telemetry creates no notification when the
  rule does not consume it.
- Experiment 0009 validates a closed derivation-trace candidate across six
  representative evidence routes. Independent Rust and Python implementations
  agree on 500 valid and 500 adversarial generated programs, reject every
  registered strengthening and trace-integrity attack, and distinguish a
  consumed unavailable fact from unused telemetry without backend-named common
  rules.

## Current decision

Continue Gate 1 only. Preserve old property records as explicit legacy
sampling. Carry the experimentally supported intent/plan/fact-authority split
and closed derivation traces into the Assurance IR candidate, but do not change
a production wire until the remaining EXP-0005 losslessness rows pass and a
versioned migration is preregistered. Next, test exact invalidation against
load-bearing and irrelevant changes. Do not freeze Assurance IR `/1`, design
final syntax, or begin native executable semantics until that boundary passes.
