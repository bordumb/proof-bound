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

Execution entries are preserved in the append-only [journal](JOURNAL.md).
Corrections are new entries rather than edits to earlier observations.

## Artifacts

The [artifact ledger](ARTIFACTS.md) indexes human and machine-readable research
artifacts. Inventory revision 2 classifies the complete registered structural
surface at the pinned baseline. Positive projection and adversarial
evidence-algebra parity have now run. Post-decision representation hardening
closes three more Q1 rows; the result remains bounded by four incomplete
forward-and-reverse rows.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0005-F001 | A required backend fact need not create a concrete backend branch in the kernel: typed family detail can declare its required schemas and generic validation can check membership. | Rust/Python validators at `f577a55`; zero concrete backend-name hits in generic kernels | Retain for the complete projection and test extension registration separately. |
| EXP-0005-F002 | Two independent implementations rejected all 20 registered ambiguity, substitution, join, cache, and status attacks with the exact same codes. | `results/2026-09-02-adversarial-evidence-algebra.json` | Bounded pass for Q2-Q4; preserve the corpus as a permanent regression suite. |
| EXP-0005-F003 | The current case projection omits fields required by Q1, including complete inventory, output, subject, closure, normalization, and TCB meaning; successful adversarial parity is not semantic sufficiency. | Result limitations and registered Q1 projection | Continue Gate 1 with a field-by-field losslessness matrix and reverse conversion. |
| EXP-0005-F004 | A strict Q1 audit finds one of 16 rows forward-complete and none reverse-complete; opaque configuration hashes and synthetic cache/subject values are insufficient substitutes for registered meaning. | `q1-losslessness-matrix.json` | Freeze the matrix as the forward and reverse acceptance gate. |
| EXP-0005-F005 | Portable reverse projection and twelve matched semantic attacks materially improve the IR, but seven of sixteen registered rows remain partial. Passing adversarial tests does not erase known representation gaps. | `q1-losslessness-matrix-r2.json`; `results/2026-09-02-q1-losslessness-decision.json` | Keep Gate 1 open. Close the seven rows before freezing `/1` or preregistering the Go holdout. |
| EXP-0005-F006 | Closed family records, canonical subject closures, and typed sealed TCB components remove three known gaps, but admission traces and complete invalidation inputs remain incomplete. | `q1-losslessness-matrix-r3.json`; `results/2026-09-02-q1-representation-hardening.json` | Keep Gate 1 open. Do not freeze `/1` or preregister the Go holdout while four rows remain partial. |
| EXP-0005-F007 | Executable presence and version are not sufficient readiness predicates: sealed npm execution additionally needed explicit dependency-fetch authority, and Lean evidence additionally needed compiled project modules. Both missing preconditions failed closed despite tool discovery succeeding. | `captures/q1-completion-r1/index.json` | Feed explicit execution capabilities into the effects/readiness workstream; do not infer runnable evidence from executable discovery alone. |
| EXP-0005-F008 | Closed registration-family records do not imply lossless portable-family conversion. Full language receipts add observed detail and human review that the current converter rejects or would replace with placeholders. | `q1-losslessness-matrix-r4.json`; `results/2026-09-02-q1-completion-capture-audit.json` | Reopen the typed-family row and implement every portable constructor before derivation traces. |
| EXP-0005-F009 | A property label and exact source identity are not a portable sampling contract. Python retains typed Hypothesis seed/framework detail, but the captured TypeScript and Rust property receipts do not retain typed sampling semantics. | `portable-family-coverage-r1.json`; `results/2026-09-02-portable-property-semantics-gap.json` | Preserve current records as visibly legacy sampling; require a new versioned wire for explicit cross-language sampling before Q1 can close. |
| EXP-0005-F010 | One closed backend-neutral family sum can project every captured portable constructor, including review, without importing production adapter types or application toolchains. A self-consistently rehashed legacy-to-explicit sampling upgrade is rejected independently. | `results/2026-09-02-portable-family-projection.json`; implementation `3dce3e3` | Retain the family sum; do not mistake converter coverage for source-wire losslessness while two sampling records remain legacy. |
| EXP-0005-F011 | Admission explanations can be canonical checked data rather than trusted prose: Rust and Python independently derive the same 23 claim traces, and changing a reported admission flag cannot change the derivation. | `results/2026-09-03-q1-derivation-traces.json`; implementation `5dc1142` | Close the publication-decision and policy-explanation rows. Carry exact consumed inputs and rules into invalidation and notification experiments. |
| EXP-0005-F012 | Artifact identity is meaningful only with its typed role: independent reports join 157 registered selectors to observed identities and retain generated, bound, and sealed roles separately. | `results/2026-09-03-q1-artifact-role-closure.json`; implementation `25ad9b2` | Close the artifact-identity row and retain role-sensitive joins in the candidate IR. |

## Outcome

Running. Q2, Q3, and Q4 have bounded passes over the registered corpus. Q1 has
an executed failed decision followed by bounded representation hardening and a
larger completion-capture audit plus exact admission traces and artifact-role
closure: fourteen of sixteen losslessness rows pass and two remain partial. Q5
remains unanswered.
Assurance IR `/1` is not frozen,
the Go holdout has not started, and programme Gate 1 remains open.
