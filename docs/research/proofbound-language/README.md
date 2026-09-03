# Proofbound language research programme

[Research programmes](../README.md) ·
[Language vision](../../notes/proofbound-language.md) ·
[Detailed plan](plan.md)

- **Status:** active
- **Created:** 2026-09-01
- **Last updated:** 2026-09-03
- **Current gate:** Gate 5 — adoption bridge and language decision
- **Latest experiment:** EXP-LANG-016 / Experiment 0023 preregistered; native Windows 11 confirmation pending
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
so the result is useful but non-confirmatory. EXP-LANG-005 subsequently
demonstrated that a mediated effect host can close the known hidden-read gap,
retain narrow invalidation, and support bounded mutation and distribution
roles. It also preserved the critical negative boundary: a registered native
subprocess is still opaque and non-reusable without independent enforcement.
EXP-LANG-006 then supplied bounded structural support for claim-oriented
uncertainty reporting. Independent engines retained every frozen critical
action and all findings while reducing interruptions from 20 to seven and
false escalations from nine to zero. Its participant phase did not run, so it
does not establish human comprehension, response-time, or fatigue benefits.
EXP-LANG-009 then validated the bounded specification suite intended for the
native parser: five reachable typed contracts accept 34/34 correct obligations
and kill six explicit semantic mutants. Independent engines agree on every
counterexample and reject 20 structural, vacuity, weakness, and integrity
attacks. This is finite specification adequacy, not parser correctness.
EXP-LANG-010 then joined those prior findings in an Assurance IR `/2` research
candidate. Independent kernels agreed across 500 valid and 500 adversarial
programmes and rejected all 28 named attacks without backend-specific common
rules. The candidate remains finite and non-production, but it unblocks the
semantic prerequisite for EXP-LANG-007.
EXP-LANG-007 then implements one canonical parser/serializer in native research
syntax and deterministic bytecode. Independent Rust and Python parsers,
compilers, VMs, and certificate checkers agree exactly; five Z3 obligations,
160 certificate rows, six semantic mutants, and 28 attacks pass within frozen
limits. This is bounded evidence for native assurance semantics, not a verified
machine-code compiler or a production language result. It unblocks the honest
mixed-language boundary test in EXP-LANG-008.
EXP-LANG-008 then executes that boundary across two foreign callers, two
phases, 48 calls, and a mixed claim graph. Independent Rust and Python kernels
produce the same canonical report and reject all 30 attacks. The native source
fact remains finite, the artifact remains assumption-bound, and both foreign
applications remain tested with explicit bridge and runtime assumptions. This
supports a bounded bridge-first architecture; it does not establish general
FFI safety, verified machine code, production usability, or a final language
decision.
EXP-LANG-011 then tested the most important remaining execution premise. A
real, separately identified macOS boundary admitted 30/30 positive Python,
Node, and Rust runs, denied all 21 live authority probes without reusable
evidence, preserved narrow invalidation, and produced byte-identical Rust and
Python reports across all 30 attacks. This supplies bounded support for an
OS-enforced effect type. The result is `revise`, not pass: the complete run
took 93,574 ms against the frozen 60,000 ms ceiling, system reads outside home
remain explicitly broad, and no Linux or Windows result exists.
EXP-LANG-012 then retained all 51 separately sandboxed executions while
scheduling them concurrently. The complete corpus fell from 93,574 ms to
6,048 ms, all 40 base and scheduler attacks rejected exactly, and independent
reports remained byte-identical. This repairs the bounded latency failure
without introducing a shared worker; platform portability remains open.
EXP-LANG-013 then compiled the same effect contract to explicit Landlock,
`no_new_privs`, environment, and seccomp dispositions in two independent
implementations. The available Linux arm64 VM returned `ENOSYS` for the
Landlock ABI query, including with its outer seccomp profile disabled. The
executor correctly emitted zero receipts and admitted no fallback, so the
study is `unanswered`: it validates fail-closed availability handling, not a
working Linux enforcement boundary.
EXP-LANG-014 then compiled the common contract to a conjunctive Windows
AppContainer, restricted-token, job-object, and exact-ACL candidate. No
Windows 11 host was available, so the platform gate emitted zero receipts and
no fallback. Independent reports and all 18 attacks agree exactly, but the
study remains `unanswered` and supplies no positive Windows enforcement
evidence.
EXP-LANG-015 then ran the frozen Linux corpus on a native Ubuntu ARM64 host
with Landlock ABI 7. Availability passed and all 51 slots executed, but the
policy denied every registered runtime before workload entry because the ELF
loader execution closure was not granted. Both independent validators rejected
the capture as `LNX-POSITIVE-OUTCOME`. The result is `revise`: the next Linux
candidate must identity-bind the loader closure without broadly granting
system-root execution.

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
| [Assurance IR `/2`](assurance-ir-v2.md) | Bounded joined semantic candidate supported by EXP-LANG-010 |
| [Workstreams](workstreams/README.md) | Bounded programmes of work and their dependencies |

## Workstream dashboard

| ID | Workstream | Status | Hypotheses | Active experiment |
|---|---|---|---|---|
| WS-IR | [Canonical Assurance IR](workstreams/assurance-ir.md) | `/2` bounded candidate supported; production parity pending | H1, H2 | EXP-LANG-010 concluded |
| WS-EA | [Evidence algebra](workstreams/evidence-algebra.md) | bounded result; broader coverage pending | H2 | EXP-0005, EXP-0008, EXP-0009 concluded |
| WS-IN | [Invalidation](workstreams/invalidation.md) | macOS candidate supported; Linux loader authority incomplete; Windows live result unanswered | H3, H9 | EXP-LANG-015 / Experiment 0022 concluded `revise` |
| WS-DSL | [Typed assurance DSL](workstreams/assurance-dsl.md) | bounded implementation complete; confirmatory result invalid | H4 | EXP-LANG-004 / Experiment 0011 concluded |
| WS-FX | [Effects and capabilities](workstreams/effects.md) | fast macOS boundary supported; Linux loader authority incomplete; Windows live portability unanswered | H5, H9 | EXP-LANG-015 / Experiment 0022 concluded `revise` |
| WS-UQ | [Uncertainty and notification quality](workstreams/uncertainty.md) | bounded machine support; human validation pending | H6 | EXP-LANG-006 / Experiment 0013 concluded |
| WS-NE | [Native executable prototype](workstreams/native-runtime.md) | bounded research bytecode supported; broader native work open | H7 | EXP-LANG-007 concluded |
| WS-AC | [Artifact correspondence](workstreams/artifact-correspondence.md) | bounded dual compilation; machine code open | H7 | EXP-LANG-007 concluded |
| WS-FB | [Foreign boundaries](workstreams/foreign-boundaries.md) | bounded bridge supported; broader boundaries open | H8 | EXP-LANG-008 concluded |
| WS-IK | [Independent kernel](workstreams/independent-kernel.md) | bounded `/2`, native, and mixed-graph differential results | H1, H2, H7, H8 | EXP-LANG-010, EXP-LANG-007, and EXP-LANG-008 concluded |

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
- EXP-LANG-005 executes six typed effect plans through independent Rust and
  Python models with identical canonical traces. All 23 registered attacks
  reject exactly, 16 authority violations stop before workload entry, the
  consumed hidden read invalidates 10/10 while an unrelated change invalidates
  0/10, and the bounded mutation and distribution outputs match exactly.
  Opaque subprocesses remain non-reusable; the external-enforcement receipt is
  synthetic and does not establish an OS sandbox.
- EXP-LANG-006 derives the same notification report in Rust and Python across
  six role-realistic scenarios. Both interfaces recall 6/6 critical actions;
  claim grouping reduces 20 raw-alert interruptions to seven decisions and
  false escalations from nine to zero while retaining all 20 findings. All 20
  attacks reject exactly. The human instrument has zero participants, so Gate
  3 product value remains open.
- EXP-LANG-009 checks a five-contract parser specification over 14 explicit
  finite carrier cases. The correct relation satisfies 34/34 obligations, all
  six mutants are killed with named counterexamples, both model reports are
  byte-identical, and 20/20 attacks reject exactly within the frozen
  complexity ceilings.
- EXP-LANG-010 joins family ceilings, complete dependencies, effect boundaries,
  artifact roles, specification adequacy, uncertainty, invalidation, and
  derivation in one backend-neutral candidate. Rust and Python agree on all
  1,000 generated programmes, every named attack rejects exactly, and both
  kernels remain below their frozen size limits. This is bounded differential
  evidence, not a production parity or formal-correctness result.
- EXP-LANG-007 parses and compiles one 856-byte native programme to exact
  22-byte research bytecode in independent Rust and Python implementations.
  The independent checker reconstructs all 160 certificate rows without
  invoking Z3, all six mutants and 28 attacks reject, and ten reports agree.
  The result is finite and assumption-bound at the artifact boundary; it does
  not establish machine-code or production-language correctness.
- EXP-LANG-008 joins that exact artifact to independent Python and TypeScript
  callers without transferring proof status across the boundary. All 48 calls,
  30 attacks, and ten report repetitions agree in independent kernels; the
  unrelated claim stays byte-identical and every runtime, bridge, and compiler
  assumption remains explicit. The result is limited to the frozen pure ABI.

## Current decision

Use the EXP-LANG-007 research bytecode, Assurance IR `/2`, and EXP-LANG-008
mixed-graph result as bounded research inputs, not production wires. EXP-0005
and the dependency-ordered EXP-LANG-001 and EXP-LANG-003--010 programme are
closed.
Preserve the experimentally supported family algebra, layered sampling,
admission traces, and artifact roles in `/2`, but do not freeze `/1` or adopt
`/2` as a production wire.
Do not select TOML, Pkl, or the custom DSL from the non-confirmatory frontend
result. Retain its separation between common effective meaning and
frontend-specific provenance, and require source-aware semantic diagnostics in
any successor. The successor now incorporates EXP-LANG-005's
mediated/opaque/external boundary and EXP-LANG-006's typed
uncertainty/claim-impact boundary without claiming current adapters are
sandboxed or that machine volume predicts human fatigue. Final syntax and
native executable semantics remain downstream. Preserve existing-language
Proofbound as the adoption bridge: the current evidence supports honest mixed
graphs, not abandoning the framework or beginning an unrestricted language
implementation.
