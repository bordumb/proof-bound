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
