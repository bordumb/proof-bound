# Proofbound language research programme

[Research programmes](../README.md) ·
[Language vision](../../notes/proofbound-language.md) ·
[Detailed plan](plan.md)

- **Status:** active
- **Created:** 2026-09-01
- **Last updated:** 2026-09-03
- **Current gate:** Gate 1 — shared semantics
- **Active experiment:** EXP-LANG-005 effect-checked replay is next; [EXP-LANG-004 / Experiment 0011](../../experiments/0011-dual-frontend-equivalence/README.md) is concluded but non-confirmatory
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
cache dependency semantics. EXP-LANG-003 then showed why adding a typed list
is insufficient: a real checker can read an undeclared file. Declared-only
identity permits stale reuse, while a global Git revision over-invalidates an
unrelated unit and cannot explain the miss through a changed dependency.
Draft `/1` is therefore not frozen. EXP-LANG-004 subsequently showed that
independent Rust and Python compilers can make TOML, a custom DSL, and
restricted Pkl agree byte-for-byte on the same bounded effective programmes.
It also failed its literal receipt-equality criterion, failed to retain source
locations through eight semantic attacks, and discovered that all three
pre-implementation programme hashes were wrong. The controls remain frozen,
so the result is useful but non-confirmatory. EXP-LANG-005 now owns the
dependency-ordered question of enforcing the read/effect boundary that
invalidation requires.

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
| WS-IR | [Canonical Assurance IR](workstreams/assurance-ir.md) | revision blocked by effect boundary | H1, H2 | EXP-0005 and EXP-LANG-003 concluded |
| WS-EA | [Evidence algebra](workstreams/evidence-algebra.md) | bounded result; broader coverage pending | H2 | EXP-0005, EXP-0008, EXP-0009 concluded |
| WS-IN | [Invalidation](workstreams/invalidation.md) | candidate rejected; effect boundary required | H3 | EXP-LANG-003 / Experiment 0010 concluded |
| WS-DSL | [Typed assurance DSL](workstreams/assurance-dsl.md) | bounded implementation complete; confirmatory result invalid | H4 | EXP-LANG-004 / Experiment 0011 concluded |
| WS-FX | [Effects and capabilities](workstreams/effects.md) | next dependency-ordered experiment | H5 | planned EXP-LANG-005 |
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
- EXP-LANG-003's closed model then derives all 26 frozen invalidation sets
  exactly in Rust and Python, with 57/57 explanation paths and no model-level
  stale retention. Its executable falsifier rejects the broader claim: a
  checker can consume an undeclared file. Keeping only declared dependencies
  permits stale reuse; adding a global source revision invalidates unrelated
  evidence and yields no typed cause. Thirteen of fourteen controlled route
  shapes had fresh baselines, one of two external holdouts passed, and the
  frozen Vitest holdout failed closed on a 6-versus-161 inventory mismatch.
- EXP-LANG-004 compiles nine TOML, custom-DSL, and restricted-Pkl pairs through
  independently written Rust and Python implementations with exact byte
  agreement and rejects all 22 registered attacks. Both typed frontends reduce
  assignments by at least 25% for the Python and TypeScript slices. The result
  is non-confirmatory: the receipt criterion incorrectly demanded equality of
  frontend-specific provenance, semantic attacks lost source locations, and
  zero of three frozen programme hashes match even though their byte lengths
  do. The controls were retained unchanged.

## Current decision

Continue Gate 1 only. EXP-0005, EXP-LANG-003, and EXP-LANG-004 are closed
rather than extended indefinitely.
Preserve the experimentally supported family algebra, layered sampling,
admission traces, and artifact roles, but do not freeze Assurance IR `/1`.
Do not select TOML, Pkl, or the custom DSL from the non-confirmatory frontend
result. Retain its separation between common effective meaning and
frontend-specific provenance, and require source-aware semantic diagnostics in
any successor. EXP-LANG-005 must now test whether an enforceable effect
boundary can make source-retained invalidation sound and precise at once.
Final syntax and native executable semantics remain downstream of that result.
