# Experiment 0005 semantic-field inventory

- **Status:** running inventory; not an IR specification
- **Baseline:** `295ad63e67bd30cc48eb8c9ee43c612de2c367c6`
- **Inventory revision:** 1
- **Coverage:** claim and evidence portable core, provenance, and current typed
  evidence-family details; manifest and adapter-observation coverage is partial

## Purpose

This document records the meaning and authority of fields that the current
producer or standalone verifier consumes. It deliberately precedes any
Assurance IR data model. A field may be renamed, combined, or split in a future
IR only after its current semantic role has been accounted for here.

The inventory is evidence for Q1 and Q2. It is not itself evidence that a
compact IR exists.

## Source surfaces inspected in revision 1

| Layer | Primary source | Role |
|---|---|---|
| Registration | `crates/proofbound-manifest/src/model.rs` | Project-authored claims, evidence units, typed route configuration, assumptions, policies, translations, and model checks |
| Observation conversion | `crates/proofbound-cli/src/compile.rs` | Independently binds adapter observations to registered units and constructs core records |
| Core semantics | `crates/proofbound-core/src/evidence.rs` | Canonical producer-side claim, evidence, assumption, provenance, and family-detail records |
| Core vocabulary | `crates/proofbound-core/src/types.rs` | Closed evidence kinds, status facets, linkage, assumptions, graph vocabulary, and tiers |
| Core derivation | `crates/proofbound-core/src/status.rs` | Claim-local evidence validation and status derivation |
| Portable wire | `crates/proofbound-verify/src/format.rs` | Independently declared closed release, claim, evidence, provenance, and family-detail receipt types |
| Independent meaning | `crates/proofbound-verify/src/verifier.rs` | Independent validation, joins, status derivation, and release consistency |
| Public contracts | `schemas/*.schema.json` | Structural wire requirements and conditional field shapes |

Revision 1 has not yet exhaustively inventoried every manifest-only field,
adapter-native observation field, graph edge, policy field, source-closure
member, or compiler-internal record. Those omissions are explicit remaining
work, not evidence that the fields are presentation-only.

## Classification vocabulary

Every assurance-relevant field must eventually receive exactly one primary IR
classification:

| Code | Category | Meaning |
|---|---|---|
| `CM` | Common mechanics | Backend-neutral identity, execution, artifact, closure, inventory, or canonicalization mechanics |
| `FS` | Evidence-family semantics | Facts that determine what a closed evidence family establishes |
| `BR` | Backend-retained detail | Tool-specific fact required for audit, invalidation, or reproduction but not generic status derivation |
| `PO` | Policy | Admission, tier, ownership, review, or organizational decision input |
| `PR` | Presentation | Reader-facing wording or rendering that does not alter machine derivation |

This classification is about semantic ownership, not serialization nesting.
For example, a field currently nested in generic provenance may ultimately be
classified as backend-retained detail.

## Authority vocabulary

| Authority | Meaning |
|---|---|
| Registered | Authored before execution and resolved from the project bundle |
| Observed | Produced from an execution boundary and independently checked against registration |
| Derived | Constructed by compiler or kernel from registered and observed facts |
| Reviewed | Human acknowledgement scoped to exact identities |
| Portable | Retained in the closed release for independent checking |

An IR field may carry more than one authority only as separate values or an
explicit equality. It must not silently replace registration with observation.

## Claim record

The core `ClaimDefinition` and portable `ClaimReceipt` are structurally aligned
at this baseline.

| Field | Class | Authority | Identity or derivation role | Initial IR direction |
|---|---|---|---|---|
| `schema` | `CM` | Registered | Freezes interpretation | Versioned claim declaration |
| `id` | `CM` | Registered | Stable claim identity and join key | `ClaimId` |
| `node_id` | `CM` | Derived from registration | Graph join key | Derive or retain with checked derivation |
| `title` | `PR` | Registered | Display only under current rules | Claim metadata |
| `statement` | `FS` | Registered | Internal property used for evidence and theorem matching | Machine claim meaning |
| `public_language` | `PR` | Registered | Reader-facing wording; must not replace `statement` | Optional presentation projection |
| `subject` | `FS` | Registered/derived identity | Binds claim to subject graph node | Typed subject reference |
| `policy` | `PO` | Registered | Selects admission rules | Policy reference |
| `tier` | `PO` | Registered | Per-claim ceiling bounded by project tier | Capability/status ceiling |
| `cited_evidence` | `FS` | Registered | Exact evidence-to-claim authorization | Evidence reference set |
| `assumptions` | `FS` | Registered | Load-bearing assumption join | Assumption reference set |
| `open_obligations` | `FS` | Registered | Prevents silent completeness claims | Open-obligation values |
| `out_of_scope` | `FS` | Registered | Bounds public interpretation | Exclusion values |
| `primary_linkage` | `PO` | Registered | Selects intended linkage profile | Linkage requirement/ceiling |
| `registered_inputs` | `FS` | Registered | Binds claim surface to registered inputs | Subject/claim input inventory |
| `registered_domain_language` | `FS` | Registered | Retains explicit bounded-domain wording | Typed domain meaning, not presentation-only |

### Claim boundary observations

- `statement` and `public_language` are correctly separate. A future IR should
  keep machine meaning and reader projection distinct.
- `registered_domain_language` is currently a string but affects the honesty of
  bounded claims; it cannot be classified as mere display text without further
  analysis.
- `node_id` appears redundant with typed identity derivation but is used as a
  portable graph join. Removing it would require an independently checked
  derivation rule and migration.

## Evidence envelope

The core `EvidenceRecord` includes a content-derived `id`; the portable release
stores `EvidenceReceipt` inside `HashedRecord`, whose `sha256` supplies the
content address. That is an encoding difference rather than a semantic
difference, but conversion must verify equality instead of copying one field.

| Semantic item | Core field | Portable field | Class | Authority | Role |
|---|---|---|---|---|---|
| Wire interpretation | `schema` | `schema` | `CM` | Derived/portable | Freezes required evidence meaning (`proofbound-evidence/3`) |
| Content identity | `id` | outer `HashedRecord.sha256` | `CM` | Derived | Content-addressed evidence identity |
| Unit identity | `unit_id` | `unit_id` | `CM` | Registered | Binds evidence to one registered execution unit |
| Graph node | `node_id` | `node_id` | `CM` | Derived | Graph join and kind checks |
| Evidence family | `kind` | `kind` | `FS` | Registered, checked against detail | Selects closed evidence semantics |
| Claim attribution | `claims` | `claim_ids` | `FS` | Registered | Exact authorized affected claim set |
| Result state | `status` | `outcome` | `FS` | Observed/derived | Non-passing states fail closed when cited |
| Evaluation mode | `evaluation_mode` | `evaluation_mode` | `FS` | Registered/observed | Distinguishes kernel and native evaluation |
| Binding mode | `binding_mode` | `binding_mode` | `FS` | Registered/derived | States permitted artifact/transcription binding mechanism |
| Formal detail | `theorem` | `theorem` | `FS` | Observed/derived | Theorem statement, attribution, environment, and axiom facts |
| Artifact detail | `artifact_binding` | `artifact_binding` | `FS` | Derived | Connects one theorem evidence identity to exact artifact identity |
| Transcription detail | `trusted_transcription` | `trusted_transcription` | `FS` | Observed/derived | Byte-equality roles and independently derived TCB identities |
| Refinement detail | `source_refinement` | `source_refinement` | `FS` | Observed/derived | Translation/theorem/premise connection |
| Bounded detail | `bounded_check` | `bounded_check` | `FS` | Registered/observed | Finite domain, solver, harness, bounds, assumptions |
| Exhaustive detail | `exhaustive_check` | `exhaustive_check` | `FS` | Registered/observed | Finite domain and evaluated cardinality |
| Mutation detail | `mutation_witness` | `mutation_witness` | `FS` | Registered/observed/derived | Exact mutant, witness, expected failure, affected claims |
| Property detail | `python_property` | `python_property` | candidate `FS`/`BR` split | Registered/observed | Framework, seed, and framework version |
| Static detail | `static_check` | `static_check` | `FS` | Registered/observed | Analyzer contract, configuration, targets, diagnostics |
| Distribution detail | `distribution_reproduction` | same | `FS` with `BR` builder identity | Registered/observed | Repeat-build digests, registered artifact, backend, inventory |
| Independence | `independence` | `independence` | `FS` | Registered/derived | Prevents common-origin evidence claiming independence |
| Target inventory | `inventoried_targets` | same | `CM` | Registered/observed equality | Authoritative nonempty surface for process evidence |
| Assumption references | `assumptions` | same | `FS` | Registered | Evidence-local load-bearing assumptions |
| Premise references | `premises` | same | `FS` | Registered/derived | Formal/refinement premise joins |
| Open obligation | `open_obligation` | same | `FS` | Registered | Explicit incomplete evidence meaning |
| Execution provenance | `provenance` | same semantic block | `CM` plus `BR` | Mixed | Identity, execution, cost, cache, and reproduction |

### Evidence envelope observations

1. `python_property` is named for one ecosystem even though
   `EvidenceKind::PropertyTest` is shared with TypeScript fast-check evidence.
   Revision 1 does not conclude whether the generic family lacks required
   sampled-property facts or whether the nested block should be split into a
   family-level sampling contract plus backend detail. This is a Q1/Q2 test.
2. Optional detail blocks plus a separate `kind` permit structurally expressible
   mismatches that validation must reject. A future algebraic IR should make the
   family/detail pairing a single tagged constructor.
3. `status`/`outcome` reports execution validity, not evidence strength. It must
   not become a generic success value from which a stronger family can be
   constructed.

## Common provenance

| Semantic item | Core | Portable | Class | Authority | Identity/validation role |
|---|---|---|---|---|---|
| Project revision | `project_revision` | same | `CM` | Registered/observed | Source-control context; nonempty |
| Worktree state | `tree_state` | same | `CM` | Observed | Clean/dirty execution context |
| Semantic closure | `semantic_source_closure` | `semantic_closure` | `CM` | Derived | Main semantic dependency identity |
| Additional closures | `additional_closures` | same | `CM` | Derived | Typed runner/presentation/external/toolchain dependencies |
| Input artifacts | `input_artifacts` | same | `CM` | Registered/observed | Exact logical name, digest, and size inventory |
| Generated artifacts | `generated_artifacts` | same | `CM` | Observed | Exact output identities |
| Tool identity | `tool` | same | `BR` | Observed, checked against registration | Native evidence producer identity |
| Adapter identity | `adapter` | same | `BR` | Derived/observed | Proofbound boundary implementation identity |
| Execution kind | `execution_kind` | same | `CM` | Derived | Distinguishes observed processes from compiler-internal derivation |
| Commands | `commands` | same | `CM` | Observed | Exact ordered program, args, and environment allowlist |
| Runs | `runs` | same | `CM` | Observed | Ordered exit and complete stream identities |
| Normalization | `normalization` | same | `CM` | Registered/derived | Names exact transformation before result hashing |
| Reproduction | `reproduction_command` | same | `CM` | Derived | Portable rerun intent; not necessarily executed in receipt |
| Start/end | `started_unix_ms`, `completed_unix_ms` | same | `CM` | Observed | Diagnostic ordering and aggregate duration checks |
| Result identity | `deterministic_result_identity` | `deterministic_result_sha256` | `CM` | Derived | Hash of normalized deterministic result |
| Unit configuration | `unit_configuration_sha256` | same | `CM` | Derived | Exact registered unit semantics |
| Cache key | derived outside record from subset | `cache_key` | `CM` | Derived | Reuse eligibility identity |
| Cache origin | `cache_origin` | derived from `reused_from` presence | `CM` | Derived | Executed versus reused distinction |
| Prior receipt | `prior_receipt_sha256` | `reused_from` | `CM` | Derived | Exact cache-chain reference |
| Resource budget | `resource_budget` | same semantic fields | `CM` | Registered | Maximum time, disk, and memory |
| Actual cost | `resource_usage` | `actual_cost` | `CM` | Observed | Time/disk and required-nullable peak memory |
| Python plugins | `python_plugins` | same | `BR` | Registered/observed | Explicit module, distribution, version, origin identity |

### Provenance observations

1. Cache material is a defined projection rather than the whole provenance:
   semantic and additional closures, input artifacts, tool and adapter
   identities, and unit configuration participate. Execution observations and
   generated artifacts intentionally do not. The IR must represent this
   projection explicitly enough to test reuse equivalence.
2. Core and portable wire encode cache origin differently. The portable form
   retains the actual cache key and optional reused receipt; core retains an
   enum and optional prior receipt. Conversion must derive and cross-check,
   never prefer one silently.
3. `python_plugins` is backend-specific information nested in the common
   provenance block. Its current placement is a concrete Q2 pressure point.
   Generalizing it to arbitrary extensions would risk opaque meaning; moving it
   to typed backend detail must preserve cache and provenance participation.
4. Resource budget and actual cost share measures but differ in nullability:
   unknown measured peak memory is not a zero value. A common IR measure type
   needs required presence with explicit unknown for observation only.

## Artifact identity

Every artifact identity is the full tuple:

```text
(logical_name, sha256, size_bytes)
```

| Field | Class | Authority | Rule |
|---|---|---|---|
| `logical_name` | `CM` | Registered or derived by fixed role | Nonempty bounded machine-matched identity; distinct from filesystem path |
| `sha256` | `CM` | Observed/derived | Exact byte identity with domain-specific surrounding joins where required |
| `size_bytes` | `CM` | Observed/derived | Prevents digest-only or forged-size substitution |

Collections require exact registered cardinality, unique logical names, and
the route-specific order or set semantics. Digest equality alone is not
artifact equality in the current model.

## Typed command and run

| Field | Class | Authority | Rule |
|---|---|---|---|
| `program` | `CM` | Registered/observed | Exact logicalized executable identity or path |
| `args` | `CM` | Registered/observed | Ordered complete argument vector |
| `environment_allowlist[].name` | `CM` | Registered | Unique portable variable name |
| `environment_allowlist[].value_sha256` | `CM` | Observed | Required-nullable value identity; secret value is never serialized |
| `environment_allowlist[].secret` | `CM` | Registered | Marks confidentiality semantics |
| `command_index` | `CM` | Derived/observed | Exact positional command/run join |
| `exit_code` | `CM` | Observed | Required-nullable; passed ordinary runs require zero, typed expected failure may differ |
| stream digests | `CM` | Observed | Complete stdout, stderr, and normalized output identities |
| `output_truncated` | `CM` | Observed | Passing evidence requires false |
| `duration_ms` | `CM` | Observed | Bounded cost and aggregate consistency |

Mutation expected failure is family semantics, not a relaxation of generic
process success. It names one exact run and allowed nonzero exit set; every
other passing-evidence run still requires zero.

## Evidence-family detail inventory

| Family | Required semantic detail | Current backend detail | Generic derivation use | Candidate IR constructor |
|---|---|---|---|---|
| Theorem | declaration, encoded statement and digest, attributed claim, proof environment, axiom audit, foundational/project axioms, evaluation mode | Lean environment and statement encoding | `PROVED` eligibility, assumption joins, theorem attribution | `UniversalSourceProof` or narrower `KernelTheorem`, retaining evaluation semantics |
| Artifact soundness | theorem evidence reference, exact artifact, binding mode | Current Lean theorem route | `ARTIFACT_BOUND` only after independent theorem/artifact joins | `ArtifactCorrespondence` backed by theorem content |
| Trusted transcription | source, committed transcription, generated candidate, reencoded source, driver, two derived TCB roles | Fixed transcription driver ABI | `TRANSCRIBED`; never artifact proof | `TrustedTranscription` |
| Source refinement | refinement theorem, representation premises, deterministic translation, pinned toolchain, generated-axiom cleanliness, strength | Charon/Aeneas translation inventory and report detail retained elsewhere | `REFINED` eligibility and premise/TCB joins | `SourceCorrespondence` |
| Bounded check | registered finite domain, solver, harnesses, unwind bounds, assumptions | Kani/solver identity | `BOUNDED_CHECKED`; never universal | `BoundedModelCheck` |
| Exhaustive check | registered finite domain, exact evaluated member count | Route-specific enumerator | `BOUNDED_CHECKED` when count matches domain | `FiniteExhaustive` |
| Property test | inventory plus, for Python, framework, seed, framework version | Hypothesis plugin facts; TypeScript fast-check currently lacks the same nested detail | Empirical `TESTED`; must not imply domain exhaustion | `SampledProperty` with an unresolved cross-backend sampling contract |
| Example test | exact nonempty inventory and passing runs | pytest, Vitest, Rust test summaries | Empirical `TESTED` | `Example` |
| Mutation witness | exact registry/preimage/mutant/postimage/witness, affected claim/guard, baseline and expected-failure runs, mutation identity | Rust, Python, and TypeScript selectors and exit conventions | Empirical `TESTED`; optional proof-term witness cannot be forged | `MutationWitness` |
| Static check | analyzer and version, config digest, exact targets, diagnostic count | mypy or `tsc` | Empirical/static `TESTED`; never functional proof | `StaticConsistency` |
| Independent check | exact inventory and independence mode | Checker ABI and report detail primarily in provenance | Empirical `TESTED`, independence-sensitive | `IndependentObservation` pending stronger semantic naming |
| Distribution reproduction | format, two run digests, registered digest, epoch, backend identity, optional npm integrity, member inventory | wheel/sdist/npm-specific archive validation | Artifact reproducibility evidence; not functional correctness | `ReproducibleArtifact` with typed format detail |
| Review | reviewer-bound exact revision/regression identities | Review manifest | Acknowledges regression; does not strengthen technical evidence | `HumanReview` |
| Assumption | assumption ledger record, affected claims, review evidence, lifecycle | Category-specific supporting material | `ASSUMED` facet and publication policy | `Assumption` node, not execution evidence |
| Open | explicit obligation | None | Keeps claim open/blocks unsupported promotion | `OpenObligation` |

## Initial backend-independence scan

These are candidates for investigation, not concluded divergences:

| Candidate | Current evidence | Why it pressures Q2 | Next check |
|---|---|---|---|
| Python plugin list in common provenance | `EvidenceProvenance.python_plugins` in core and verifier | Generic provenance knows a language-specific extension concept | Trace cache, validation, release, and status consumers before proposing placement |
| Python-named property detail | `EvidenceRecord.python_property` and `EvidenceReceipt.python_property` | Shared `PropertyTest` family has ecosystem-specific field naming and asymmetric TypeScript population | Compare Hypothesis and fast-check registered/observed semantics field by field |
| Node-specific compiler branches | `compile.rs` branches on `AdapterKind::NodeTest` for exits, static tool names, and runtime identities | Some branches may be producer boundary checks; others may encode family meaning | Classify every branch as registration binding, backend retained detail, or generic semantic leak |
| Distribution format branching | wheel, sdist, and npm validation differ | Archive semantics are legitimately format-specific, but generic reproducibility meaning should not be | Separate format checker facts from the shared two-run equality constructor |
| Lean-specific theorem structure | theorem record carries Lean-oriented environment and statement encoding | Universal proof may require prover-neutral proposition identity while preserving logic-specific axioms | Compare with a proposed Verus observation without forcing false equivalence |

## Portable release context still to inventory

The following release-level records are known to affect independent meaning and
remain for revision 2:

- compiled release project, revision, tier, and tree state;
- graph nodes, edges, and mutual theorem groups;
- reported status projection and publication decision;
- assumption and premise records;
- policy profiles and their evidence requirements;
- source-closure members, kinds, digests, file modes, and union semantics;
- sealed release files;
- release envelope and payload identity; and
- compiled-project/cache-only state that does not enter the portable release.

## Manifest and observation work still to inventory

Revision 2 must map registration and observation authority for:

- every `ClaimManifest` field;
- every `EvidenceUnitManifest` field and conditional route block;
- model-check and translation manifests;
- mutation registries;
- assumption, premise, policy, and review manifests;
- adapter protocol request and response envelopes;
- common adapter observation fields;
- Python and Node observation extensions;
- Lean, Kani, and Aeneas direct records or observations; and
- compiler-internal review, source-closure, and artifact records.

Until these are mapped, Q1 is explicitly unanswered.

## Revision 1 results

Revision 1 establishes a concrete baseline rather than an IR:

- claim machine meaning and reader presentation are already distinct;
- the evidence envelope is close to a tagged union but remains a kind plus
  optional detail blocks;
- common provenance contains both backend-neutral mechanics and at least one
  language-specific retained detail;
- cache semantics are a deliberate projection that must survive IR extraction;
- full artifact identity is name, digest, and size, not digest alone;
- required-null observations carry meaning distinct from omission and zero;
- evidence-family distinctions are present but not yet uniformly represented
  across Python and TypeScript sampled properties; and
- no evidence yet supports the claim that the common kernel is backend-free.

The next inventory revision should complete release-level records and trace all
concrete backend-name branches in generic producer and verifier code.
