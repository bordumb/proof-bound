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
