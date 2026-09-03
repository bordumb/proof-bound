# Draft Assurance IR `/1`

[Programme dashboard](README.md) ·
[Field inventory](../../experiments/0005-assurance-ir-extraction/semantic-field-inventory.md) ·
[Frozen corpus](../../experiments/0005-assurance-ir-extraction/corpus/README.md)

- **Status:** research draft; non-normative; partially implemented; not frozen
- **Draft version:** `proofbound-assurance-ir/1`
- **Input baseline:** `295ad63e67bd30cc48eb8c9ee43c612de2c367c6`
- **Experiment:** EXP-0005
- **Wire status:** this is not a replacement for any current Proofbound schema

This document records the smallest semantic boundary found in inventory
revision 2 and refined by the current Rust/Python research prototype. It is a
design under test, not a claim that EXP-0005 has passed. The completion-capture
audit plus the exact-trace and artifact-role follow-ups finds fourteen of
sixteen semantic rows complete and two partial. No current
manifest, receipt, cache, release, or verifier may emit or accept the schema
name above until a later normative specification adopts it.

## 1. Goal

Assurance IR is the common meaning between authoring frontends, evidence
backends, and a small independent kernel. It should let TOML manifests, a typed
DSL, Pkl or CUE, and a future native Proofbound language describe the same
assurance programme without teaching the kernel about pytest, Vitest, Kani,
Lean, Aeneas, npm, or wheel.

It does not make unlike evidence equivalent. An example, sampled property,
finite exhaustive check, bounded model check, theorem, source correspondence,
and artifact correspondence remain different constructors with different
derivation power.

```text
authoring frontend       evidence backend
       │                       │
       ▼                       ▼
 registered programme   typed observation
       │                       │
       └──── checked conversion ────┐
                                    ▼
                          canonical Assurance IR
                                    │
                      independent validation + derivation
                                    │
                                    ▼
                         status, impact, publication
```

The checked conversion boundary is intentionally outside the kernel. It may
know that Hypothesis uses a pytest plugin or that Aeneas emits a translation
report. It may not choose evidence strength or write a derived status.

## 2. Non-goals

Draft `/1` does not define:

- final surface syntax;
- an executable programming language;
- proof search or theorem construction;
- an operating-system sandbox;
- a plugin ABI for arbitrary status rules;
- a replacement for native tool output;
- a claim that current Aeneas refinement evidence has executed; or
- a compatibility promise for this research-only encoding.

Opaque extension data may be retained for audit, identity, and invalidation.
It cannot add a graph edge, evidence constructor, status role, or policy rule.

## 3. Design laws

1. **Authority is explicit.** Registered, observed, derived, and reviewed facts
   cannot silently overwrite one another. Equality across authorities is a
   checked relation.
2. **Evidence is a closed sum.** A record has one constructor, not a kind plus
   a collection of optional detail objects.
3. **Statuses are outputs.** Frontends and adapters cannot author `PROVED`,
   `REFINED`, `ARTIFACT_BOUND`, or `ADMITTED`.
4. **Identity is typed.** A digest without its domain and logical role is not a
   complete identity.
5. **Unknown required meaning fails closed.** An unknown constructor, graph
   relation, policy component, required extension, or canonicalization rule is
   rejected.
6. **Presentation cannot become machine meaning.** Public wording can explain
   a claim but cannot replace its registered machine statement.
7. **Backend detail survives without governing the kernel.** Tool identities,
   plugin modules, selectors, archive formats, and native reports remain bound
   for audit and invalidation.
8. **Invalidation is declared.** Cache eligibility is computed from a typed
   dependency projection, not a parallel accidental field subset.
9. **No numeric assurance score exists.** Formal, linkage, assumption, and
   policy facets remain independent.

## 4. Root model

The pseudo-IDL below is descriptive. `Set<T>` means canonical lexical order in
the encoding with duplicate rejection. `List<T>` preserves semantic order.
`Option<T>` requires explicit absence in the typed model; a required-nullable
wire value is represented by `Known<T> | Unknown`, never by omission.

```text
AssuranceProgram {
  schema: "proofbound-assurance-ir/1"
  project: Project
  claims: Set<Claim>
  evidence: Set<Evidence>
  assumptions: Set<Assumption>
  premises: Set<Premise>
  policies: Set<AdmissionPolicy>
  graph: AssuranceGraph
  closures: Set<SourceClosure>
  sealed_artifacts: Set<ArtifactIdentity>
  tcb_components: Set<TcbComponent>
  backend_bindings: Set<BackendBinding>
}

Project {
  id: ProjectId
  revision: RevisionIdentity
  tier: Tier
  tree_state: Clean | Dirty
}
```

`AssuranceProgram` is the semantic compilation unit. A portable release adds a
payload identity and reported derivation projection around it; private compiler
state and authoring file paths are not part of this root.

## 5. Identities and values

```text
ArtifactIdentity {
  logical_name: LogicalName
  sha256: Sha256
  size_bytes: U64
}

SourceClosure {
  id: Sha256
  kind: Semantic | Runner | Presentation | ExternalEvidence | Toolchain
  members: List<ArtifactIdentityByPath>
}

ToolIdentity {
  role: ToolRole
  name: BoundedText
  version: BoundedText
  executable: Option<ArtifactIdentity>
}

BackendDependency {
  role: BoundedText
  name: BoundedText
  version: BoundedText
  identity: Sha256
}

TcbComponent {
  name: BoundedText
  version: BoundedText
  identity: Sha256
}
```

An artifact is equal only when logical name, digest, and size are equal. A
closure is equal only under its declared member ordering and closure kind.
Backend dependencies cover facts such as Python plugin module/distribution
identity without embedding `python_plugins` in common provenance.

## 6. Claims

```text
Claim {
  id: ClaimId
  subject: NodeId
  subject_closure: SubjectClosure
  machine_meaning: ClaimMeaning
  presentation: Option<ClaimPresentation>
  cited_evidence: Set<EvidenceId>
  assumptions: Set<AssumptionId>
  premises: Set<PremiseId>
  open_obligations: Set<OpenObligation>
  out_of_scope: Set<Exclusion>
  registered_inputs: Set<LogicalName>
  admission: ClaimAdmission
}

SubjectClosure {
  schema: "proofbound-ir-subject-closure/1"
  identity: Sha256
  selectors: Set<LogicalName>
  members: Set<ArtifactIdentity>
}

ClaimMeaning {
  statement: BoundedText
  formal_declaration: Option<DeclarationIdentity>
  statement_encoding: Option<EncodingId>
  statement_identity: Option<Sha256>
  foundational_axioms: Set<AxiomId>
  bounded_domain: Option<BoundedDomain>
}

ClaimPresentation {
  title: BoundedText
  public_language: Option<BoundedText>
}

ClaimAdmission {
  policy: PolicyId
  tier_ceiling: Option<Tier>
  required_linkage: Option<LinkageFacet>
}
```

The split answers only the structural portion of OQ-003. Whether some current
free-form domain wording should become a richer proposition language remains
open. Conversion must retain it as machine meaning until that question is
resolved. A registration subject closure is computed from normalized,
non-symlink project paths and exact member bytes. Its identity is independently
recomputed; changing a selector and refreshing only the closure digest does not
preserve meaning.

## 7. Evidence envelope

```text
Evidence {
  id: EvidenceId
  unit: UnitId
  node: NodeId
  claims: Set<ClaimId>
  outcome: Passed | Failed | Drifted | Missing
  inventory: Set<InventoryItem>
  assumptions: Set<AssumptionId>
  premises: Set<PremiseId>
  open_obligation: Option<OpenObligation>
  evaluation: Option<Kernel | Native>
  binding: Option<BindingMode>
  family: EvidenceFamily
  provenance: Provenance
  backend: BackendProvenance
}
```

The evidence identity is a domain-separated digest of canonical bytes without
the `id` field. The exact domain belongs to a later prototype; it must not reuse
an existing `proofbound-evidence/3` identity domain.

`outcome = Passed` means the registered observation completed and validated.
It says nothing about evidence family strength. A failed or drifted cited
record makes the relevant derivation fail closed.

Every constructor detail is intended to be a closed typed record. Registration
projections currently type property seed/framework, mutation registry, distribution
format/artifact/epoch, bounded-domain, theorem, subject, and bound-artifact
meaning. The detail must reconstruct the registered family configuration
exactly; a parallel opaque configuration digest is not sufficient. Complete
portable captures initially showed that conversion was incomplete for
observed mutation, property, static-check, independent-check, distribution,
theorem, bounded-check, artifact, transcription, and human-review detail. A
subsequent closed Rust/Python projection now covers all 45 captured family
records and rejects family-detail substitution independently. Draft `/1` still
does not satisfy the lossless rule across a full release because two property
records can only inhabit the explicit legacy state described below.

## 8. Closed evidence algebra

```text
EvidenceFamily =
    Example(ExampleEvidence)
  | SampledProperty(SampledPropertyEvidence)
  | FiniteExhaustive(FiniteExhaustiveEvidence)
  | BoundedModelCheck(BoundedModelCheckEvidence)
  | StaticConsistency(StaticConsistencyEvidence)
  | IndependentObservation(IndependentObservationEvidence)
  | MutationWitness(MutationWitnessEvidence)
  | UniversalSourceProof(UniversalSourceProofEvidence)
  | SourceCorrespondence(SourceCorrespondenceEvidence)
  | ArtifactCorrespondence(ArtifactCorrespondenceEvidence)
  | TrustedTranscription(TrustedTranscriptionEvidence)
  | ReproducibleArtifact(ReproducibleArtifactEvidence)
  | HumanReview(HumanReviewEvidence)
  | OpenEvidence(OpenEvidence)
```

### 8.1 Empirical constructors

```text
ExampleEvidence {
  targets: Set<InventoryItem>
}

SampledPropertyEvidence {
  targets: Set<InventoryItem>
  sampling: ExplicitSampling | LegacyBackendSampling
}

ExplicitSampling {
  framework: BoundedText
  framework_version: BoundedText
  seed: U64
  generator_identity: Option<Sha256>
}

LegacyBackendSampling {
  contract_identity: Sha256
  reason: "sampling-detail-not-yet-portable"
}

StaticConsistencyEvidence {
  analyzer: ToolIdentity
  configuration: Sha256
  targets: Set<InventoryItem>
  diagnostics: U64
}

IndependentObservationEvidence {
  targets: Set<InventoryItem>
  independence: Independent | SharedOrigin
}
```

`LegacyBackendSampling` is a visible migration state, not a silent default. It
preserves the current TypeScript and Rust gaps while OQ-001 remains open. The
captured TypeScript receipt binds the exact test source and configuration
identity, but does not retain its fast-check framework, version, seed, or run
count as typed portable facts. The Rust property-labelled receipt likewise has
no typed sampling record. A converter may use the configuration identity as a
legacy contract identity for invalidation; it may not claim that the digest
reconstructs the missing semantics. Both sampling variants derive empirical
`TESTED` at most. Neither constructor can be decoded as finite exhaustion or
proof.

### 8.2 Finite and bounded constructors

```text
FiniteExhaustiveEvidence {
  domain: BoundedDomain
  evaluated_members: U64
}

BoundedModelCheckEvidence {
  domain: BoundedDomain
  solver: ToolIdentity
  harnesses: Set<InventoryItem>
  unwind_bounds: Map<InventoryItem, U64>
  model_assumptions: List<BoundedText>
}
```

Finite exhaustion requires the registered cardinality to be known and equal to
the observed evaluated member count. It defaults to `TESTED`; only an explicit
policy may admit it as `PROVED`. Bounded model checking derives
`BOUNDED_CHECKED`, never universal proof.

### 8.3 Mutation constructor

```text
MutationWitnessEvidence {
  mutation_id: MutationId
  subject: SubjectIdentity
  guard: BoundedText
  registry: ArtifactIdentity
  target_preimage: ArtifactIdentity
  mutant: ArtifactIdentity
  target_postimage: ArtifactIdentity
  witness_source: ArtifactIdentity
  check_id: InventoryItem
  baseline_run: RunIndex
  expected_failure: ExpectedFailure
  affected_claims: Set<ClaimId>
  mutation_identity: Sha256
  proof_term: Option<EvidenceId>
}

ExpectedFailure {
  run: RunIndex
  allowed_exit_codes: Set<I32>
}
```

The baseline and mutant executions remain separate observed runs. The mutant's
non-zero exit is retained truthfully; it is not rewritten to success. Without a
separately valid proof term, mutation evidence contributes empirical testing
only.

### 8.4 Formal and correspondence constructors

```text
UniversalSourceProofEvidence {
  declaration: DeclarationIdentity
  proposition: EncodedProposition
  attributed_claim: ClaimId
  proof_environment: EnvironmentId
  axiom_audit: AxiomAudit
}

SourceCorrespondenceEvidence {
  theorem: EvidenceId
  representation_premises: Set<PremiseId>
  deterministic_translation: Bool
  pinned_toolchain: Bool
  generated_axioms_clean: Bool
  strength: Full | Partial
}

ArtifactCorrespondenceEvidence {
  theorem: EvidenceId
  artifact: ArtifactIdentity
  binding: BindingMode
}
```

`UniversalSourceProof` may derive `PROVED` subject to policy and axiom rules.
It does not imply that shipping source or artifact bytes implement the proved
model. `SourceCorrespondence` and `ArtifactCorrespondence` are separate joins
that can derive `REFINED` and `ARTIFACT_BOUND` only after independently checking
the referenced theorem and exact subject/artifact identities.

The encoded proposition and axiom audit remain logic-specific typed data. The
kernel needs their declared semantics and identities but does not execute Lean,
Verus, or another prover.

### 8.5 Trusted transcription

```text
TrustedTranscriptionEvidence {
  source: ArtifactIdentity
  committed_transcription: ArtifactIdentity
  observed_candidate: ArtifactIdentity
  reencoded_source: ArtifactIdentity
  driver: ArtifactIdentity
  transcriber_role: TcbRole
  reencoder_role: TcbRole
}
```

The two byte equalities and distinct role identities derive `TRANSCRIBED`.
They do not derive source proof, source correspondence, or artifact proof.

### 8.6 Reproducible artifact

```text
ReproducibleArtifactEvidence {
  format: FormatId
  run_digests: NonEmptyList<Sha256>
  registered_digest: Sha256
  source_date_epoch: U64
  builder: ToolIdentity
  member_inventory: Set<InventoryItem>
  format_integrity: Option<FormatIntegrity>
}
```

All run digests must equal the registered digest. Format-specific archive
validation remains a checked producer-boundary fact. Reproducibility does not
establish functional correctness.

## 9. Provenance

```text
Provenance {
  revision: RevisionIdentity
  tree_state: Clean | Dirty
  semantic_closure: ClosureId
  additional_closures: Set<ClosureId>
  inputs: Set<ArtifactIdentity>
  generated: Set<ArtifactIdentity>
  tool: ToolIdentity
  adapter: ToolIdentity
  execution: ObservedProcesses | CompilerInternal
  commands: List<Command>
  runs: List<Run>
  normalization: NormalizationId
  reproduction: Command
  interval: TimeInterval
  result_identity: Sha256
  unit_configuration: Sha256
  budget: ResourceBudget
  usage: ResourceUsage
  cache: CacheObservation
}

BackendProvenance {
  dependencies: Set<BackendDependency>
  retained_facts: Set<RetainedBackendFact>
}
```

`RetainedBackendFact` has a registered schema, required/optional disposition,
and either a closed typed value or a canonical payload identity. Known facts
that carry semantic meaning must use the typed value. Unknown required fact
schemas fail closed. Unknown optional facts may be displayed and hashed but
cannot participate in derivation. This is not an extension point for new
evidence semantics.

Commands retain exact program, ordered arguments, and an environment allowlist
whose values are represented as `Known<Sha256> | Unknown`. Runs retain exact
indices, required exit state, complete stream digests, normalized digest,
truncation state, and duration. Passing ordinary runs require exit zero and no
truncation; only a family constructor such as mutation may name an allowed
expected-failure run.

### 9.1 TCB ledger binding

Portable conversion strictly decodes the sealed `proofbound-tcb-ledger/1`
artifact into `TcbComponent` records, reconstructs its canonical bytes, and
checks the sealed logical name, digest, and size. Every observed tool and
adapter identity must then match one typed component. This prevents a
self-consistently rehashed but semantically substituted TCB component from
surviving as an opaque sealed-file change.

## 10. Cache dependency projection

```text
CacheDependencies {
  unit_configuration: Sha256
  semantic_closure: ClosureId
  additional_closures: Set<ClosureId>
  input_artifacts: Set<ArtifactIdentity>
  tools: Set<ToolIdentity>
  backend_dependencies: Set<BackendDependency>
  execution_inputs: Set<ExecutionInputIdentity>
}
```

The common kernel computes the cache key from canonical
`CacheDependencies`. A backend converter is responsible for discovering a
complete `execution_inputs` set under its sealed execution model. The kernel
does not know Cargo workspaces, Python import rules, or npm locks; the backend
cannot omit a required dependency without failing its typed conversion and
adversarial invalidation tests.

Generated artifacts, child output, timestamps, usage, and prior receipt are not
pre-execution dependencies. A reused record retains both the new cache key and
the exact prior receipt identity. This is a provisional answer shape for
OQ-004, not its resolution.

## 11. Graph, assumptions, and policy

The graph retains the current closed node and edge vocabularies and checked
endpoint table. Mutual theorem groups remain the only cycle exception and must
share one proof environment.

```text
Assumption {
  id: AssumptionId
  statement: BoundedText
  category: AssumptionCategory
  owner: BoundedText
  rationale: BoundedText
  scope: BoundedText
  affected_claims: Set<ClaimId>
  review_evidence: Set<EvidenceId>
  discharge_plan: BoundedText
  source_citation: Option<BoundedText>
  state: Proposed | Accepted | Discharged | Rejected
  depends_on: Set<AssumptionId>
}

AdmissionPolicy {
  id: PolicyId
  components: Set<PolicyComponent>
  allowed_foundational_axioms: Set<AxiomId>
  allowed_project_axioms: Set<AssumptionId>
  exhaustive_as_proof: Bool
  require_no_assumptions: Bool
  native_premise_rule: Option<NativePremiseRule>
  additional_required_evidence: Set<EvidenceConstructorId>
}
```

Policy selects what may be admitted; it cannot reinterpret a constructor.
Review records approve exact revision regressions and never add technical
evidence strength.

## 12. Derivation output

```text
DerivationResult {
  claim: ClaimId
  formal: Open | Tested | BoundedChecked | Proved | Invalid
  linkage: ModelOnly | Transcribed | Refined | ArtifactBound
  assumption: None | Assumed | Invalid
  policy: Admitted | Blocked(Set<PolicyBlocker>)
  evidence_assessments: Set<EvidenceAssessment>
  bounded_domains: Set<BoundedDomain>
  open_obligations: Set<OpenObligation>
  out_of_scope: Set<Exclusion>
  trace: DerivationTrace
}
```

The trace identifies the exact constructors, graph joins, assumptions,
premises, policies, and blockers that produced each facet. It is the basis for
impact-oriented notifications: a changed backend dependency should notify only
claims whose derivation or publication actually depends on it, while a stale
non-load-bearing observation should not become another undifferentiated alert.

The trace is recomputed. A serialized reported result is accepted only when it
equals independent derivation.

The EXP-0005 completion prototype makes the claim trace explicit:

```text
DerivationTrace {
  claim_id: ClaimId
  formal_value_and_rule: FacetDerivation
  linkage_value_and_rule: FacetDerivation
  assumption_value_and_inputs: AssumptionDerivation
  policy_id: PolicyId
  effective_tier: Tier
  required_policy_components: Set<PolicyComponent>
  satisfied_policy_components: Set<PolicyComponent>
  load_bearing_evidence: Set<EvidenceId>
  open_obligations: Set<OpenObligationId>
  blockers: Set<PolicyBlocker>
}

PublicationTrace {
  admitted_claims: Set<ClaimId>
  blocked_claims: Set<ClaimId>
  blockers: List<ClaimId × PolicyBlocker>
}
```

The trace is not an explanation string. It is a canonical checked projection
whose inputs are typed claims, evidence, policies, assumptions, and project
tier. The prototype derives identical bytes in Rust and Python for the three
complete language captures and rejects all six registered trace substitutions.

## 13. Canonical encoding

The first prototype should use strict canonical JSON because both current
implementations already have independent canonicalization experience. That is
an implementation choice, not a surface-language commitment.

Draft requirements:

- UTF-8 only;
- no duplicate object keys;
- no unknown fields;
- integers only within declared ranges;
- no floating-point values;
- object keys sorted by Unicode scalar value;
- set elements sorted by their canonical encoded value and duplicate-rejected;
- lists preserve semantic order;
- explicit schema IDs on the root and every independently evolving nested
  semantic record;
- SHA-256 text in one lowercase prefixed representation;
- canonical round trip must reproduce identical bytes; and
- unknown required schemas or enum values fail closed.

Every domain hash has a unique domain string. Existing evidence, release,
mutation, and cache domains remain frozen. IR `/1` receives new domains only
after the prototype defines exact preimages and test vectors.

## 14. Validation phases

1. **Decode:** reject noncanonical, duplicate, unknown, omitted, aliased, or
   out-of-range values.
2. **Local type validation:** validate identities, collection rules, tagged
   constructor detail, and authority shape.
3. **Registration joins:** bind claims, evidence, assumptions, premises,
   policies, graph nodes, closures, and backend registrations exactly.
4. **Observation joins:** compare observed inventory, configuration, artifacts,
   commands, and typed family facts to registration.
5. **Evidence validation:** validate one closed constructor and its provenance.
6. **Graph validation:** validate endpoints, identities, cycles, and proof
   environments.
7. **Derivation:** compute independent status facets and trace.
8. **Policy:** compute admission and blockers from the derived facets.
9. **Release comparison:** compare recomputed results to any reported status and
   payload identities.

A later phase never repairs a failure from an earlier phase.

## 15. Conversion from current Proofbound records

Conversion is explicitly versioned:

```text
proofbound manifests + observations
    --current-version semantics-->
proofbound-assurance-ir/1

proofbound compiled release /3
    --portable conversion-->
proofbound-assurance-ir/1 + reported release projection
```

Rules:

- existing schema IDs keep their current meaning;
- conversion selects behavior from the source schema before decoding detail;
- old singular command or incomplete provenance shapes are rejected rather
  than inferred;
- absent required-nullable fields are not treated as explicit unknown;
- `python_plugins` becomes backend dependencies without losing module,
  distribution, version, or origin identity;
- Python property detail becomes `ExplicitSampling`;
- the current TypeScript property route becomes `LegacyBackendSampling` until
  a registered seed/generator contract exists;
- current archive formats map to `ReproducibleArtifact` plus required retained
  format facts;
- current kind plus optional-detail records map to exactly one constructor or
  fail; and
- reported statuses never populate derivation inputs.

No schema is redefined in place. A project that cannot be converted losslessly
receives a migration diagnostic and remains on its current frozen semantics.

## 16. Frozen corpus examples

The first prototype must demonstrate at least these projections:

| Corpus case | Required constructor/result |
|---|---|
| `IR-PY-002` | `SampledProperty(ExplicitSampling(hypothesis, seed, version))` and backend plugin dependency |
| `IR-TS-002` | `SampledProperty(LegacyBackendSampling(...))`, visibly not finite exhaustion |
| `IR-PY-003`, `IR-TS-003` | One `StaticConsistency` constructor despite different analyzers |
| `IR-PY-004`, `IR-TS-004`, `IR-RS-003` | One mutation constructor with route-specific retained backend facts |
| `IR-PY-005`, `IR-TS-005` | One reproducibility constructor with format-specific retained integrity facts |
| `IR-SEM-001`–`IR-SEM-006` | Exact formal/linkage/assumption/policy projection |
| `IR-REL-001` | Exact graph, policy, closure, cache/reuse, sealed-file, status, and envelope projection |

Round-trip means equality of the registered semantic projection, not equality
between source TOML, current receipt JSON, and IR JSON bytes.

## 17. Required falsification work

This draft is not accepted until two independent implementations agree on the
positive corpus and reject at least:

- omitted required authority;
- duplicate or reordered set member;
- list order substitution;
- family/detail substitution;
- example-to-exhaustive and property-to-proof upgrades;
- source-proof-to-artifact-proof upgrade;
- static-check-to-functional-proof upgrade;
- unknown required backend fact;
- mismatched claim subject;
- mismatched artifact name, digest, or size;
- assumption omission or state change;
- closure-member and cache-dependency omission;
- reused receipt with a changed dependency;
- noncanonical JSON and duplicate object keys;
- stale reported status; and
- old schema bytes interpreted as a new schema.

## 18. Open decisions

| Question | Draft treatment | What would resolve it |
|---|---|---|
| OQ-001 sampled properties | Explicit sampling where registered; visible legacy contract otherwise | A cross-framework registration and observation experiment |
| OQ-002 plugin identity | Typed backend dependencies outside common provenance | Cache, effects, and portability tests across Python and Node plugins |
| OQ-003 claim language | Machine/presentation split, current strings retained | A typed proposition and bounded-domain study |
| OQ-004 cache projection | Backend supplies typed dependencies; common code hashes them | Zero-false-retention invalidation experiment |
| OQ-006 effects | Provenance records observed authority only | Static capability model plus OS enforcement experiment |

The unresolved Q1 boundary is narrower than this broader question list:
lossless explicit sampling for two legacy receipts and complete transitive
cache dependencies remain blockers to freezing `/1`.
| OQ-008 frontend | IR is frontend-neutral | Equivalent TOML, Pkl/CUE, and DSL compilation study |

## 19. Acceptance boundary

Draft `/1` is ready for prototype implementation when:

- every frozen corpus source maps without an unclassified field;
- every evidence route maps to exactly one constructor;
- required retained backend facts have a schema and identity;
- canonical domains and test vectors are registered before implementation;
- two implementations can be built without sharing decode or derivation code;
  and
- the adversarial corpus is preregistered.

Until those conditions and EXP-0005's pass criteria are met, this document is a
research hypothesis expressed as a data model—not the Proofbound language and
not a production assurance contract.
