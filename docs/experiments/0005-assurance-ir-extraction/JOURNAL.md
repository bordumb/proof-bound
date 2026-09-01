# Experiment 0005 journal

[Experiment registration](README.md) · [Artifact ledger](ARTIFACTS.md)

This journal is append-only after each entry lands. Corrections are new entries
that reference the statement being corrected.

## 2026-09-01 — Preregistration

Pre-registered. Not started. No Assurance IR model or experiment-specific
semantic-field inventory was created before the Questions section was
committed.

## 2026-09-01 — Start

Pinned the subject and implementation baseline to registration commit
`295ad63e67bd30cc48eb8c9ee43c612de2c367c6` and began the semantic-field
inventory. The first bounded slice covers the claim, evidence envelope,
provenance, and portable family-detail records in core and the standalone
verifier; manifest and observation coverage remains explicitly partial. See
[semantic-field-inventory.md](semantic-field-inventory.md).

## 2026-09-01 — Research filesystem scaffold

Separated programme synthesis under `docs/research/proofbound-language/` from
this experiment's preregistration and observations. Added a structured partial
field-inventory scaffold, artifact ledger, corpus index, and immutable-results
directory. This is an organizational change, not an EXP-0005 result and not an
Assurance IR design.

## 2026-09-01 — Semantic inventory revision 2

Completed the registration-to-release structural inventory at the pinned
baseline. Revision 2 adds project, claim, evidence-unit, translation,
model-check, mutation, policy, review, adapter protocol and observation, graph,
assumption, premise, closure, cache, compiled-state, release, and derived-status
coverage. It also records the concrete backend branch audit.

The audit found no concrete backend-name branch in core status derivation or
the standalone verifier's status algebra. Concrete backend knowledge remains
in registration binding, observation conversion, cache dependency discovery,
and typed retained detail. Two current generic-record defects remain explicit:
Python plugin metadata is nested in common provenance and sampled-property
detail is Python-named and asymmetric with TypeScript. No experiment question
is answered by the inventory alone.

## 2026-09-01 — Positive projection corpus revision 1

Froze 20 positive projection cases against exact Git blob bytes at baseline
`295ad63e67bd30cc48eb8c9ee43c612de2c367c6`. The corpus covers Python and
TypeScript example, property, static, mutation, and distribution registrations;
Kani, Lean, and Rust registrations; six backend-free semantic status cases;
and the canonical portable release fixture.

The inactive Aeneas refinement example remains explicitly non-executed. Its
translation registration is pinned as supporting input, while source-refinement
semantics come from the positive conformance case. This avoids turning an
aspirational demo into fabricated observation evidence. No converter or
projection comparison has run, so Q1, Q3, and Q5 remain unanswered.

## 2026-09-01 — Draft Assurance IR `/1`

Drafted a non-normative Assurance IR from inventory revision 2 and the frozen
positive corpus. The model separates authority, uses a closed evidence sum,
keeps status as derived output, moves backend dependencies outside common
provenance, names an explicit cache-dependency projection, and preserves
distinct empirical, bounded, formal, correspondence, transcription, and
reproducibility meanings.

The draft does not hide the current sampled-property asymmetry: registered
Hypothesis facts map to explicit sampling, while the current TypeScript route
maps to a visible legacy backend-sampling state pending OQ-001. It also records
the inactive Aeneas route honestly. The schema name is reserved only inside the
research draft; no implementation may emit it yet. Q1–Q5 remain unanswered.

## 2026-09-01 — Adversarial and canonical preregistration

Before implementing either prototype, froze 20 independent adversarial
mutations and their expected rejection phases/codes. Also froze the canonical
JSON contract, five research-only domain strings, and 15 expected domain-hash
vectors. This prevents either implementation from choosing encodings or
negative cases after observing the other's behavior.

The registered attacks cover every minimum Q3 category plus cache dependency,
required-unknown, claim-attribution, evidence-strength, and reported-linkage
attacks. They remain unexecuted.

## 2026-09-01 — Initial projection parity run

At implementation commit `757f42096b896d3bdb41b896a46bfad3dcdc2ca4`,
ran a typed Rust producer and separately written Python checker over all 20
frozen positive cases. The producer verifies source identities and projects
registration, semantic-status, and release cases. The Python checker imports no
producer types, reconstructs the same projection directly from frozen source,
and independently checks canonical bytes and domain identities.

The implementations agreed on all 20 cases and all 15 preregistered canonical
domain vectors. The canonical projection identity was
`sha256:357cc0d521f46e9f360d06c378d32e0c2b1acd1de72ab38b5d8686e6fcfdd558`.
This is deliberately a boundary prototype: it does not yet materialize the full
AssuranceProgram, rederive every status from the evidence algebra, or execute
the 20 preregistered adversarial transformations. No EXP-0005 question is
therefore marked passed.

## 2026-09-02 — Adversarial corpus correction before execution

While materializing the adversarial harness, IR-ADV-003 was found to reverse a
singleton run list. That operation is an identity transformation and could not
test the registered ordering invariant. No adversarial case had been executed.

The adversarial corpus therefore advances to revision 2 before execution.
IR-ADV-003 now changes the sole source-derived run's command index from zero to
one and retains `IR-PROVENANCE-RUN-ORDER` as its expected rejection. The other
19 cases are unchanged. Results must bind revision 2 and its new digest; the
initial positive-only result remains bound to revision 1.

## 2026-09-02 — Adversarial evidence-algebra run

At implementation commit `f577a55dc01e70dfcd595a45b71855ae052db58b`,
expanded every positive projection into a canonical per-case Assurance IR
document. Independently implemented Rust and Python validators rederive the
registered family/detail relationship, subject and artifact joins,
assumptions, claim attribution, cache dependency and reuse binding, run order,
and status ceilings without executing an evidence backend.

Both validators rejected all 20 adversarial revision-2 cases with the exact
registered codes. They also retained agreement on all 20 positive cases and 15
canonical vectors. A literal backend-schema branch discovered during the first
local run was removed before the implementation commit: typed sampled-property
detail now declares its required fact schemas, and the generic validator only
checks declaration membership. Neither generic validator contains a concrete
backend name.

This is bounded evidence for Q2, Q3, and Q4. Q1 remains unanswered because the
prototype does not yet preserve every registered projection field or implement
reverse conversion. Q5 remains unanswered because complete versioned migration
has not been exercised. The machine-readable result records those limits and
must not be cited as completion of Experiment 0005.
