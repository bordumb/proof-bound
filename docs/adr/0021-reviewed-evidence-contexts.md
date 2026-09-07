# ADR 0021: Release evidence contexts are reviewed activation sets

- **Status:** Accepted
- **Date:** 2026-09-07
- **Decision owners:** Proofbound maintainers
- **Related:** ADR 0002, ADR 0020, and Runtime feedback PBF-0009

## Context

Some evidence subjects exist only during a release build. Exact native bundles
are the motivating case: separate runners create different architecture bytes,
while ordinary source checks and unsupported developer hosts have neither
artifact. Requiring every release observation during every check makes the base
workflow impossible. Loading generated evidence manifests from an ignored
directory is worse because it lets mutable configuration cross the clean-tree
boundary.

Evidence availability is not evidence meaning. A release workflow needs a way
to activate a reviewed subset without changing a claim, profile, ceiling,
assumption, bound, or dependency.

## Decision

Proofbound will support closed, named **evidence contexts**. A context is a
reviewed activation set for evidence units that remain inactive during the base
check. Version 1 is intentionally narrow: contextual units must use exact
artifact observation evidence from ADR 0020.

### Registration

A version 2 project manifest registers a strict sorted set of context names and
a nonempty subset that is required for releases. A contextual evidence unit:

- is a tracked, reviewed manifest matched by the project's ordinary
  `evidence_units` inventory;
- uses evidence-unit schema version 5;
- names exactly one registered context; and
- remains explicitly cited by every affected claim through the claim's existing
  evidence inventory.

Context names use the same closed lowercase identifier grammar as artifact
roles. Generated, ignored, untracked, duplicate, or ambiguously matched context
manifests are not reviewed registrations and fail closed.

### Activation

`proofbound check --evidence-context <name>` selects one registered context. A
base check selects none. In both cases Proofbound executes all noncontextual
evidence for the selected claims. A contextual check additionally executes only
the units owned by the selected context.

Claim derivation includes noncontextual citations plus citations owned by the
selected context. Inactive contextual citations do not become missing evidence,
failed evidence, assumptions, or synthetic open records. They establish
nothing in that compiled result.

Context selection is invalid with claim or trust-profile filtering. It always
describes one full-project evidence closure. Reproduction of a contextual unit
selects that unit's registered context.

### Release boundary

Compiled project state records the selected context. A project that declares
required release contexts cannot create a release from base state or from an
unregistered context. The release command rechecks the clean reviewed tree,
the full-project selection, the context registration, and the compiled context
before writing bytes.

Version 4 compiled releases and release envelopes carry the selected context
when exact observations are present. The independent verifier requires a
nonempty closed context for contextual observation releases, retains it in the
verification report, and rejects context substitution through canonical
payload and envelope validation. The context changes no claim facet.

### Fail-closed rules

Compilation or release rejects:

- an unknown, empty, malformed, or duplicate context;
- a context requested for a version 1 project;
- a context unit outside evidence-unit schema version 5;
- a context unit whose manifest is not tracked in the reviewed tree;
- execution or citation of evidence owned by an inactive context;
- a contextual check combined with a partial claim or profile selection;
- a release from base state when release contexts are required;
- a release context that was changed after the compiled check;
- context omission or substitution in a version 4 portable receipt; and
- any attempt to derive stronger formal or linkage status from context
  selection.

### Compatibility

Version 1 projects have no contexts and retain their existing check and release
behavior. Version 2 projects opt into the feature. Older tools reject the new
project schema. New tools accept both versions but never infer a context from
host state, environment variables, paths, or evidence output.

## Implementation sequence

1. Freeze this decision and its context attack inventory.
2. Add project and evidence-unit registration with tracked-manifest validation.
3. Add deterministic base/context selection and compiled-state identity.
4. Enforce required contexts at release and project context into version 4
   receipts and independent verification reports.
5. Execute the frozen producer/verifier corpus.
6. Adopt contexts in Proofbound Runtime's two native release jobs.

## Consequences

Projects can keep fast, portable base checks while requiring exact generated
evidence for release. The reviewed configuration remains immutable, and a
context is not a skip mechanism or a new trust profile.

The first version supports only exact artifact observations. Broader optional
evidence should be added only after another concrete consumer demonstrates that
the same activation semantics preserve honest claim status.
