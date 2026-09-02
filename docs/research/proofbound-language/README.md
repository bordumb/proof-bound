# Proofbound language research programme

[Research programmes](../README.md) ·
[Language vision](../../notes/proofbound-language.md) ·
[Detailed plan](plan.md)

- **Status:** active
- **Created:** 2026-09-01
- **Last updated:** 2026-09-02
- **Current gate:** Gate 1 — shared semantics
- **Active experiments:** [Experiment 0005 — Assurance IR extraction](../../experiments/0005-assurance-ir-extraction/README.md) and [Experiment 0007 — Rust sampled-property holdout](../../experiments/0007-rust-sampling-holdout/README.md); [Experiment 0006](../../experiments/0006-explicit-sampling-contract/README.md) concluded the Python/TypeScript sampling slice
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
| WS-EA | [Evidence algebra](workstreams/evidence-algebra.md) | running | H2 | EXP-0005; EXP-0007 |
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

## Current decision

Continue Gate 1 only. Preserve old property records as explicit legacy
sampling. Register a Rust property-framework holdout against the EXP-0006
contract before proposing a production wire; then recapture the portable
family only after versioned producer adoption. Do not execute the
preregistered derivation-trace attacks, freeze Assurance IR `/1`, preregister
the Go holdout, or design final syntax and native executable semantics until
the lossless boundary passes. Versioned migration remains the subsequent Q5
gate.
