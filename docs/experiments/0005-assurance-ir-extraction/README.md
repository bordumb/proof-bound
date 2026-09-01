# Experiment 0005: Assurance IR extraction

- **Status:** running
- **Registered:** 2026-09-01 (commit of this Questions section)
- **Started / concluded:** 2026-09-01 / —
- **Subject:** Proofbound repository and conformance corpus at
  `295ad63e67bd30cc48eb8c9ee43c612de2c367c6`
- **Proofbound:** baseline `295ad63e67bd30cc48eb8c9ee43c612de2c367c6`;
  pin later experiment implementation commits in each executed trial
- **Operator:** Codex (GPT-5)

## Why this experiment

Proofbound currently preserves assurance meaning across manifests, adapter
observations, compiler records, graph nodes, releases, and an independently
implemented verifier. Python and TypeScript support expanded that surface and
made the central architectural risk concrete: a supposedly language-neutral
core may instead become a union of backend-specific schemas and conditionals.

Before designing a Proofbound language, this experiment tests whether the
existing system actually contains a smaller semantic model that can serve as a
canonical Assurance IR. The experiment is useful even if the language idea is
abandoned because it should expose duplicated validation, implicit joins, wire
drift, and backend knowledge that has leaked into generic derivation.

## Questions (pre-registered)

1. **Q1 — Semantic sufficiency.** Can a draft Assurance IR represent the
   assurance-relevant meaning of the registered example-test, sampled-property,
   static-check, bounded-check, mutation-witness, formal-proof,
   source-correspondence, trusted-transcription, and reproducible-distribution
   routes? **Pass:** for every selected positive corpus case, an explicit
   projection from the existing typed record to the draft IR and back preserves
   the exact claim ID, evidence family, subject and artifact identities,
   inventory, assumptions, typed detail, status facets, publication decision,
   and cache/reuse semantics that the current producer or verifier consumes.
   Every assurance-relevant source field appears exactly once in the registered
   field-classification matrix as common mechanics, evidence-family semantics,
   backend-retained detail, policy, or presentation. **Falsifier:** any consumed
   field has no lossless representation, must be interpreted from prose, maps
   ambiguously to more than one category, or changes one of the registered
   projections.
2. **Q2 — Backend-independent kernel.** Can generic validation and status
   derivation operate over evidence families without knowing concrete tools or
   programming languages? **Pass:** the independent IR checker has no
   dependency on adapter crates or application toolchains; its common envelope
   and generic derivation contain no branch on concrete names such as pytest,
   Vitest, mypy, TypeScript, Kani, Aeneas, Lean, Verus, Cargo, npm, wheel, or
   sdist. Tool-specific facts remain in typed family detail or opaque retained
   provenance and cannot author status. **Falsifier:** adding or validating a
   selected route requires a concrete backend-name conditional in generic
   status derivation, or independent checking requires executing or linking the
   originating toolchain.
3. **Q3 — Canonical and fail-closed interpretation.** Can two implementations
   assign one meaning to the draft IR and reject ambiguous encodings?
   **Pass:** the producer-side prototype and a separately implemented checker
   agree on canonical bytes, typed identities, validation result, derivation
   trace, and publication decision for every positive case and every generated
   case within the registered bounded corpus. The adversarial corpus covers at
   least omission, duplicate, alias, order substitution, unknown required
   semantics, mismatched subject, mismatched artifact, changed assumption,
   inventory skew, and noncanonical encoding; none is incorrectly accepted.
   **Falsifier:** one implementation accepts an adversarial case the other
   rejects, canonical round-trip bytes differ, or an unknown required semantic
   element is ignored.
4. **Q4 — Evidence distinctions survive normalization.** Does extracting a
   common IR preserve the epistemic boundary among examples, sampled
   properties, finite exhaustive checks, bounded model checks, universal source
   proofs, and artifact correspondence? **Pass:** the draft evidence algebra
   has distinct constructors for these meanings; no serialized `passed`
   Boolean or common success envelope can be deserialized as a stronger family;
   and focused negative cases demonstrate that sampled evidence cannot derive
   universal proof, source proof without correspondence cannot derive artifact
   proof, and static consistency cannot derive functional correctness.
   **Falsifier:** compatibility requires flattening two of these meanings or a
   family substitution reaches an equal or stronger status.
5. **Q5 — Migration without silent reinterpretation.** Can existing projects
   adopt the IR without changing the meaning of their current versioned records?
   **Pass:** the Python, TypeScript, Rust/Aeneas, Kani, Lean, mutation,
   transcription, and distribution reference cases retain their current
   per-claim status facets and publication decisions through an explicitly
   versioned conversion. Older records are either converted under their frozen
   semantics or rejected with a migration diagnostic; no existing schema ID is
   redefined. **Falsifier:** a current positive reference changes status or
   publication result, an old schema is silently assigned new required meaning,
   or conversion depends on unrecorded ambient state.

## Registered projections and equality

Q1 and Q5 compare the following projection for each selected claim rather than
requiring a new IR encoding to be byte-equal to an older wire format:

```text
claim ID
subject identity
public and internal claim meaning
formal / linkage / assumption status facets
publication decision and blocking reasons
evidence unit ID and evidence family
inventoried targets
input, generated, and bound artifact identities
assumptions and exclusions
semantic and runner closure identities
typed evidence-family detail
execution and normalization provenance
cache origin and reuse eligibility
TCB and tool identities
```

Collections compare using the ordering or set semantics declared by their
existing schema. Canonical bytes compare only within the same versioned
encoding. A migration passes when the declared semantic projection is equal;
it must not claim that differently versioned bytes are identical.

## Initial corpus

- Python exact pytest example;
- Python seeded Hypothesis property;
- Python mypy static check;
- Python mutation replay;
- Python wheel reproduction;
- TypeScript exact Vitest example;
- TypeScript seeded fast-check property;
- TypeScript `tsc` static check;
- TypeScript mutation replay;
- TypeScript npm package reproduction;
- Kani bounded model check;
- Lean theorem evidence;
- Charon/Aeneas source correspondence;
- trusted transcription;
- Rust mutation witness; and
- proof-free release-smoke/compiler-internal evidence.

The first running journal entry must pin the exact fixture or repository paths,
record IDs, and Proofbound commit used. Cases may be removed only through an
append-only journal entry that marks the associated question unanswered or
failed; the pre-registered scope must not be silently narrowed.

## Scope

- **In:** semantic field inventory; canonical IR design; explicit evidence
  algebra; conversion of existing records; producer/checker differential tests;
  status, invalidation, and cache semantics already represented by current
  Proofbound behavior; selected positive and adversarial corpus cases.
- **Out:** final authoring syntax; native executable application semantics;
  general effect system; proof search; new evidence strength; redesign of
  existing evidence routes merely to make the IR smaller; performance claims
  beyond recording prototype measurements; production migration.

## Procedure

1. Pin the subject and implementation commits and enumerate exact corpus cases.
2. Build a semantic-field inventory from manifests through portable receipts.
3. Mark every field by authority, identity participation, validation owner,
   derivation use, canonicality, and intended IR category.
4. Record generic logic that branches on concrete adapters or languages.
5. Draft the minimal IR and evidence algebra from that inventory.
6. Implement producer-side conversion without changing existing records.
7. Implement a separate checker without importing producer types.
8. Run positive projection parity.
9. Generate and run the bounded adversarial corpus.
10. Measure kernel dependencies, backend-name conditionals, encoding size,
    conversion loss, and producer/checker agreement.
11. Dispose every divergence before concluding the questions.

## Journal (append-only)

- **2026-09-01** — Pre-registered. Not started. No Assurance IR model or
  experiment-specific semantic-field inventory was created before this
  Questions section was committed.
- **2026-09-01** — START. Pinned the subject and implementation baseline to
  registration commit `295ad63e67bd30cc48eb8c9ee43c612de2c367c6` and began
  the semantic-field inventory. The first bounded slice covers the claim,
  evidence envelope, provenance, and portable family-detail records in core
  and the standalone verifier; manifest and observation coverage remains
  explicitly partial. See [semantic-field-inventory.md](semantic-field-inventory.md).

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|

## Outcome

Running. Q1–Q5 remain unanswered.
