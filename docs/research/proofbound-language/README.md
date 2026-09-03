# Proofbound language research programme

[Research programmes](../README.md) ·
[Language vision](../../notes/proofbound-language.md) ·
[Detailed plan](plan.md)

- **Status:** active
- **Created:** 2026-09-01
- **Last updated:** 2026-09-03
- **Current gate:** Gate 1 — shared semantics
- **Active experiment:** EXP-LANG-003 invalidation preregistration is next; [Experiments 0005–0009](../../experiments/README.md) are concluded
- **Purpose:** Determine whether a small assurance kernel can support existing repositories, a typed assurance DSL, and a native high-assurance language without flattening evidence meaning or expanding into backend-specific exceptions.

## Current position

No language decision has been made. Experiment 0005 concluded the first
Assurance IR extraction with a useful falsification. Fifteen of sixteen
registered semantic field classes survive exact forward and reverse
projection, but portable evidence does not retain the complete role-typed
dependency projection needed to justify cache reuse without ambient inference.

The positive semantic-projection corpus is frozen and a non-normative
[Assurance IR `/1` draft](assurance-ir-v1.md) records the candidate that was
tested. Independent Rust and Python implementations agree on the registered
positive and adversarial corpora. Versioned sampling extensions, exact
admission traces, and artifact-role closure closed every remaining row except
cache dependency semantics. Draft `/1` is therefore not frozen. The next
dependency-ordered step is EXP-LANG-003, which must test a source-retained
dependency model and its invalidation precision.

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
| WS-IR | [Canonical Assurance IR](workstreams/assurance-ir.md) | blocked by invalidation result | H1, H2 | EXP-0005 concluded |
| WS-EA | [Evidence algebra](workstreams/evidence-algebra.md) | bounded result; broader coverage pending | H2 | EXP-0005, EXP-0008, EXP-0009 concluded |
| WS-IN | [Invalidation](workstreams/invalidation.md) | next | H3 | EXP-LANG-003 |
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
- The EXP-0005 completion trace projects those principles through all 23
  claims in the frozen Python, TypeScript, and Rust releases. Rust and Python
  derive byte-identical claim and publication traces and reject all six
  preregistered trace attacks, so publication decision and policy explanation
  are no longer implicit fields.
- The artifact-role follow-up joins every registered selector to an exact
  observed identity across 39 executable units. Generated, nested bound, and
  sealed artifacts remain distinct roles, and both implementations reject all
  five registered role/byte/omission/alias attacks.
- The Q1 finalization closes explicit sampling without rewriting historical
  receipts, but triggers its cache stop condition. A cache key proves equality
  only under the producer that computed it; it does not expose which code,
  permissions, tools, absence facts, or external contracts made that equality
  assurance-relevant.

## Current decision

Continue Gate 1 only. EXP-0005 is closed rather than extended indefinitely.
Preserve the experimentally supported family algebra, layered sampling,
admission traces, and artifact roles, but do not freeze Assurance IR `/1`.
EXP-LANG-003 must make dependencies source-retained and test exact invalidation
against both load-bearing and irrelevant changes. Final syntax and native
executable semantics remain downstream of that decision.
