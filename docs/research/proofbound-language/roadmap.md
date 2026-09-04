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

Current result: the EXP-LANG-005 research candidate repairs the known
declaration-only falsifier for mediated operations and fails closed for opaque
processes. Gate 1's semantic model is therefore unblocked for revision, but a
production enforcement claim still requires a real sandbox/runtime experiment.
EXP-LANG-010 composes that boundary with the prior algebra, invalidation,
uncertainty, specification, and artifact-role results in a bounded `/2`
candidate. Gate 1 has a native-experiment target, but production parity and
real enforcement remain open.

EXP-LANG-011 / Experiment 0018 tested that premise on one real macOS mechanism.
The project boundary, narrow invalidation, independent interpretation, and all
registered attacks passed across Python, Node, and Rust. The overall decision
is `revise` because 93,574 ms exceeded the 60,000 ms ceiling; system reads
outside home and platform portability also remain open. Gate 1 may retain the
typed enforcement candidate, but production cache authority remains blocked.

EXP-LANG-012 / Experiment 0019 repairs the frozen latency failure with a
6,048 ms concurrent run while retaining 51 distinct sandboxes and receipts.
All base and scheduling attacks pass independent validation. Gate 1 therefore
has a bounded fast macOS candidate; Linux and Windows parity and a supported
production mechanism still block production cache authority.

EXP-LANG-013 / Experiment 0020 maps all nine authority classes to explicit
Linux dispositions, but the available Linux arm64 VM returns `ENOSYS` for the
Landlock ABI probe. It correctly produces no workload receipts and no fallback
evidence. Gate 1 therefore remains blocked: the fail-closed availability path
is supported, while live Linux enforcement is unanswered and Windows remains
untested.

EXP-LANG-014 / Experiment 0021 independently compiles a conjunctive Windows
candidate but has no supported Windows 11 execution environment. Its host gate
produces zero receipts and no simulated result. Gate 1 therefore retains only
bounded macOS execution evidence; both portable live boundaries still require
confirmatory runs.

EXP-LANG-015 / Experiment 0022 reaches a real Landlock ABI 7 host and executes
all 51 frozen slots. It falsifies the first live Linux policy: all 30 permitted
workloads are denied before entry because the registered dynamic-loader
premise is not represented as execute authority. Linux is now a concrete
`revise`, rather than an availability `unanswered`; Windows remains untested.

EXP-LANG-017 / Experiment 0024 repairs that falsifier with one exact,
identity-bound ELF-interpreter role. The native Ubuntu ARM64 run passes all
five registered questions: 30 permitted executions, 21 denied probes, zero
denied reuse, byte-identical independent reports, and 40 exact attack
rejections. Gate 1 now has bounded macOS and Linux candidates; native Windows
confirmation still blocks a cross-platform result.

EXP-LANG-018 / Experiment 0025 repairs Windows process initialization with an
exact PE/runtime/profile/object closure. All three runtimes enter under the
conjunctive AppContainer boundary, the run stays below the latency ceiling,
and independent validators reject all 30 attacks exactly. It does not close
Gate 1: Python's ten successful processes produce CRLF rather than the frozen
LF output, and connection-refused on all three network probes is not evidence
of policy denial. A preregistered successor must repair the platform-neutral
byte contract and use a proven-reachable network oracle without weakening the
retained Windows boundary.

EXP-LANG-019 / Experiment 0026 executes that successor and concludes `revise`.
All 30 outputs are exact, the 18 non-network probes are denied, three live
controls connect, zero sandbox connections are accepted, all 38 attacks reject
exactly, independent reports agree, and non-reuse and latency invariants hold.
The three network attempts return timeouts or a process deadline rather than
the frozen exact access-denied results. Gate 1 therefore has bounded Windows
execution and independently observed network non-delivery, but not the exact
Windows denial fact required for cross-platform closure. The next candidate
must type that distinction and test an independent kernel-level observer.

EXP-LANG-020 / Experiment 0027 preregisters that candidate. It preserves the
entire EXP-0026 execution matrix and accepts a Windows network denial only from
an exact synchronous error or a read-only WFP capability-drop event bound to
the fresh package, staged application, flow, and execution window. It cannot
mutate WFP collection or firewall policy.

## Gate 2 — Authoring and authority

Required: WS-DSL and WS-FX.

Exit only if equivalent frontends emit identical canonical effective meaning,
frontend-specific receipts preserve provenance, meaningful errors fail before
execution, and effects prevent demonstrated defects without unacceptable
ceremony. EXP-LANG-004 did not exit this gate because its frozen controls were
invalid and semantic errors lost source origins.

EXP-LANG-005 satisfies the bounded authority half of this gate. The frontend
confirmation and source-aware diagnostic requirements remain open.

## Gate 3 — Product value

Required: WS-UQ and structured user studies.

Exit only if claim-oriented uncertainty improves impact assessment or reduces
irrelevant escalation without increasing missed critical consequences.

Current result: EXP-LANG-006 passes the bounded structural prerequisites. Its
candidate retains all frozen critical consequences and findings while reducing
interruptions and false escalations. The participant phase did not run, so
Gate 3 remains open and no claim about human assessment speed or fatigue is
established.

## Gate 4 — Native feasibility

Required: WS-NE and WS-AC.

Exit only if a native prototype produces independently checkable functional
assurance and an honest source-to-artifact story stronger than a comparable
existing-language integration.

Prerequisite result: EXP-LANG-009 validates the native parser's bounded
five-role contract suite against six semantic mutants and 20 adequacy attacks.
This prevents the known frozen vacuity and weak-specification forms; it does
not provide evidence about native code or artifacts. EXP-LANG-010 then
validates the joined semantic target across a 500/500 differential corpus.
EXP-LANG-007 now validates one canonical source and deterministic research
bytecode artifact with independent Rust/Python compilation and checking. Five
Z3 conditions, 160 certificate rows, six semantic mutants, and 28 attacks pass
within the frozen budget. This supports bounded native semantics and unblocks
mixed-language research, but Gate 4 remains open: the artifact is VM bytecode,
not native machine code; dual compilation is assumption-bound; and no release
or mature-language cost comparison was performed.

## Gate 5 — Adoption bridge

Required: WS-FB plus final WS-IK validation.

Proceed to a language specification only if mixed-language migration is honest
and usable, the independent implementations agree, and existing-language
Proofbound remains a first-class product.

Current result: EXP-LANG-008 passes the bounded technical honesty and
independent-agreement criteria for one pure packet ABI, two runtimes, and a
finite corpus. It keeps foreign application claims tested and preserves all
remaining assumptions while selectively strengthening their artifact linkage.
Gate 5 does not fully exit: human usability, broader FFI semantics, production
enforcement, and the requirement that existing-language Proofbound remain a
first-class product need evidence beyond this research fixture.

## Strategic outcomes

- **Remain a framework** if no compact cross-ecosystem semantic core survives.
- **Ship an assurance DSL** if typed authoring is valuable but native execution
  adds disproportionate compiler and ecosystem cost.
- **Develop a native language** only if Gate 5 passes.
