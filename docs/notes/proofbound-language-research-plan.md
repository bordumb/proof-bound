# Proofbound language research plan

[Documentation map](../README.md) · [Working notes](README.md) ·
[Language vision](proofbound-language.md)

- **Status:** exploring
- **Created:** 2026-09-01
- **Last updated:** 2026-09-01
- **Purpose:** Define a staged, falsifiable research programme for determining whether Proofbound should grow from an assurance system for existing repositories into a native high-assurance programming language.

## Summary

The research programme should answer one central question:

> Can one small semantic kernel represent and independently check justified
> confidence across existing-language projects and native programs without
> erasing meaningful distinctions or accumulating backend-specific exceptions?

The programme deliberately starts below surface syntax. Its first products are
a canonical Assurance IR, a formal evidence algebra, derivation and
invalidation rules, and a small independent checker. A typed assurance DSL is
then built over that foundation. Only after those layers work across existing
Python, TypeScript, Rust, Lean, and formal evidence should the project prototype
native executable code.

The current Proofbound product remains the adoption bridge throughout. A native
language is successful only if it strengthens that product rather than
forking its concepts, verifier, and ecosystem into a second system.

## Outcomes sought

By the end of the programme, the project should be able to make an evidence-led
decision among three outcomes:

1. **Remain an assurance system.** The shared kernel is valuable, but native
   executable code adds insufficient benefit or excessive trusted complexity.
2. **Ship an assurance DSL.** Typed claims, assumptions, evidence, effects, and
   policies materially improve authoring, while application code remains in
   existing languages.
3. **Develop a native language.** A small executable prototype demonstrates
   meaningful assurance, usable diagnostics, independently checked proof and
   artifact correspondence, and a credible mixed-language adoption path.

The research must make all three outcomes acceptable. It should not be designed
to justify a language decision already made.

## Non-goals during research

Until the semantic and trust foundations pass their gates, do not prioritize:

- finalized language syntax;
- self-hosting;
- a public package registry;
- a garbage collector or general async runtime;
- web frameworks and broad application libraries;
- a bespoke theorem prover or SMT solver;
- replacing Lean, Verus, or other proof-producing systems;
- general-purpose-language performance competition;
- compatibility with every existing tool; or
- marketing the prototype as production-ready.

## Research principles

### Semantics before syntax

Every frontend must compile into a separately specified canonical model.
Attractive syntax is not evidence that the underlying distinctions are sound.

### Normalize mechanics; preserve epistemology

Commands, identities, inventories, closures, and artifacts should share common
representations. Examples, sampled properties, bounded checks, theorem proofs,
artifact reproduction, and human review must retain different meanings.

### Backends report facts; the kernel assigns meaning

No adapter, solver, compiler, or project-authored extension may manufacture a
status such as `PROVED` or `ADMITTED`. It emits a typed observation or proof
object; the independent kernel applies platform-owned derivation rules.

### Existing repositories are research instruments

Purpose-built fixtures establish protocol behavior, but external Python,
TypeScript, Rust, and formal projects reveal hidden ecosystem assumptions.
Every major semantic proposal should be tested against both.

### Every research claim needs a falsifier

Experiments must register failure conditions before implementation. “The
prototype worked” is insufficient without a defined adversarial or comparative
test.

### The independent checker is the architectural constraint

The checker must not need application toolchains or frontend evaluators. If a
portable release requires installing pytest, Node, Cargo, Verus, Lean, or the
native Proofbound compiler, the architecture has failed.

## Core hypotheses

| ID | Hypothesis | Primary falsifier |
|---|---|---|
| H1 | Existing evidence routes can compile into a small canonical Assurance IR without losing assurance-relevant detail. | The IR requires proliferating tool-named core variants or cannot reproduce current verdicts. |
| H2 | Evidence strength can be expressed as a closed algebra with statically constrained composition. | Common routes require ad hoc status logic outside the algebra, or unlike evidence is flattened to preserve compatibility. |
| H3 | Invalidation can be derived from exact semantic dependencies with materially less noise than repository-wide reruns. | Selective invalidation misses a load-bearing change or invalidates most of the graph for routine unrelated changes. |
| H4 | A typed assurance DSL can reduce authoring errors and duplication while compiling identically to existing manifests. | Equivalent TOML and DSL projects diverge semantically, or users cannot understand the generated effective programme. |
| H5 | An effect and capability model can prevent demonstrated ambient-authority defects before evidence execution. | The model either misses known defects or becomes so permissive or detailed that it offers no practical static protection. |
| H6 | First-class uncertainty produces more actionable, lower-volume engineering signals than tool-oriented alerts. | Users take longer to assess impact, misunderstand residual uncertainty, or receive no measurable reduction in irrelevant escalation. |
| H7 | A small native executable subset can connect code, specification, proof, build, and release more strongly than existing-language adapters. | Its checker or compiler trust cost exceeds the assurance gained, or the same outcome is simpler with an existing verified language. |
| H8 | Mixed native and foreign components can share one graph without pretending empirical correspondence is formal proof. | Foreign boundaries become untyped escape hatches or make native assurance claims unintelligible. |

## Target architecture under investigation

```text
Existing-language projects                  Native Proofbound programme
manifests + typed adapters                   code + specs + proofs + effects
             │                                           │
             └──────────────────┬────────────────────────┘
                                ▼
                     Canonical Assurance IR
                     ├─ subject identities
                     ├─ claims and meanings
                     ├─ assumptions and exclusions
                     ├─ observations and proof objects
                     ├─ evidence and bindings
                     ├─ authority and effects
                     ├─ uncertainty and invalidation
                     └─ policy and derivations
                                │
                                ▼
                     Independent semantic kernel
                                │
                                ▼
                   graph + receipt + release verdict
```

The canonical IR and kernel are shared products. The TOML frontend, assurance
DSL, native compiler, and tool adapters are replaceable producers.

## Workstream A: canonical Assurance IR

### Research questions

- Which fields are universal across all evidence families?
- Which backend details affect assurance meaning and must be retained?
- Can inventories, closures, command provenance, assumptions, and artifacts be
  represented without tool-specific concepts in the kernel?
- Which identities are content-derived, context-derived, or human-assigned?
- Can the IR support deterministic canonicalization and versioned evolution?
- Can an older verifier reject unknown semantics without rejecting unrelated
  known evidence?

### Method

1. Inventory the semantic fields consumed by the producer, core, and standalone
   verifier for every current route.
2. Classify each field as common mechanics, evidence-family semantics,
   backend-specific retained detail, policy, or presentation.
3. Define a versioned IR independent of TOML and Rust serialization types.
4. Build lossless converters from current manifests and receipts.
5. Compile the Python, TypeScript, Rust/Aeneas, Kani, Lean, mutation,
   transcription, and distribution demonstrations.
6. Compare canonical graphs, status facets, assumption propagation, and release
   verdicts with the existing implementation.
7. Mutate or omit each assurance-relevant field and require independent
   rejection or a precisely bounded semantic effect.

### Deliverables

- field inventory and classification matrix;
- draft Assurance IR specification;
- canonical encoding and domain-separation rules;
- Rust producer prototype;
- independently implemented decoder/checker prototype;
- legacy-to-IR migration corpus;
- cross-route adversarial corpus; and
- size, dependency, and complexity measurements for the checker.

### Exit criteria

- At least five materially different evidence families compile into the IR.
- Existing demonstrations retain identical claim statuses and publication
  decisions.
- Backend-specific detail remains available without driving generic status
  through backend-name conditionals.
- Canonical round trips are byte-stable.
- Unknown required semantics fail closed.
- The standalone checker does not link application adapters or toolchains.
- Independent mutation tests find no accepted field omission, substitution,
  duplicate, alias, or order ambiguity in the tested corpus.

### Stop condition

Stop language work and narrow the IR if it becomes primarily a union of tool
schemas rather than a small assurance model.

## Workstream B: evidence algebra and derivation logic

### Candidate evidence types

```text
Example<Subject, Inventory>
SampledProperty<Subject, Generator, Seed, Cases>
Exhaustive<Subject, FiniteDomain>
BoundedModelCheck<Subject, Bounds>
StaticConsistency<Subject, AnalyzerContract>
MutationWitness<Claim, Mutant, Witness>
UniversalSourceProof<Subject, Proposition, Assumptions>
SourceCorrespondence<SourceA, SourceB>
ArtifactCorrespondence<Source, Artifact>
ReproducibleArtifact<Artifact, Builder>
TrustedTranscription<Source, Transcription>
HumanReview<Scope, Revision>
```

### Research questions

- Which evidence families are fundamental and which are compositions?
- Which type parameters must affect identity and invalidation?
- How are conjunctive, alternative, and conflicting evidence represented?
- What does evidence weakening mean formally?
- Which derivations are monotonic under evidence addition or removal?
- How should finite, sampled, bounded, and universal quantification compose?
- How should assumptions constrain otherwise strong evidence?

### Method

1. Encode the current status rules as explicit inference rules.
2. Model evidence families as algebraic data types rather than status labels.
3. Define legal constructors and compositions.
4. Define illegal coercions and produce compile-time counterexamples.
5. Mechanize a small subset of the algebra in Lean or another proof assistant.
6. Prove or test key properties:
   - evidence cannot construct a stronger family through serialization alone;
   - removing evidence cannot strengthen a claim;
   - adding an assumption cannot remove an existing assumption obligation;
   - sampled evidence cannot derive universal evidence;
   - model proof without correspondence cannot derive artifact proof; and
   - review acknowledges a regression but does not change evidence strength.
7. Differentially test the algebra implementation against the existing core
   and independent verifier.

### Deliverables

- evidence algebra specification;
- inference-rule catalogue;
- machine-checked or property-tested metatheory subset;
- positive composition corpus;
- forbidden-coercion corpus; and
- diagnostics catalogue explaining failed derivations.

### Exit criteria

- Every current status derivation has an explicit rule.
- The producer and independent checker agree over a generated corpus.
- At least one real current manifest error becomes an unrepresentable typed
  programme rather than a runtime validation error.
- Formal and empirical evidence cannot be confused through a common “passed”
  representation.

## Workstream C: dependency, cache, and invalidation semantics

### Research questions

- What is the minimal complete dependency set for an assurance conclusion?
- Can semantic dependencies be distinguished from execution dependencies and
  presentation files?
- How do permission bits, absence, directory topology, tools, environment, and
  external contracts enter identity?
- Can selective invalidation remain both sound and usefully narrow?
- Can cache equivalence be stated and checked as a semantic property?

### Method

1. Represent every evidence result as a derivation over typed dependencies.
2. Reuse past cache failures as adversarial fixtures: external source files,
   executable permission changes, missing paths, negative module resolution,
   generated-state drift, and changed manifests.
3. Create a change matrix across code, tests, configuration, documentation,
   tools, assumptions, policies, and artifacts.
4. Predict invalidation from the IR, execute fresh checks, and compare results.
5. Generate repository mutations automatically and test for false retention and
   false invalidation.
6. Measure the fraction of the graph re-executed for representative changes.

### Measures

- **Sound retention rate:** retained evidence whose fresh execution remains
  semantically equivalent.
- **False-retention count:** stale evidence accepted after a load-bearing
  change; target zero.
- **Invalidation precision:** affected evidence divided by all invalidated
  evidence.
- **Re-execution reduction:** work avoided relative to a complete fresh run.
- **Explanation coverage:** invalidations with a specific dependency path and
  claim consequence.

### Exit criteria

- Zero false retention across the registered adversarial corpus.
- Documentation-only changes preserve unrelated evidence.
- Representative leaf-code changes do not invalidate the entire project.
- Every invalidation report identifies a changed dependency and affected claim.

## Workstream D: typed assurance DSL

### Research questions

- Does a language improve correctness beyond replacing punctuation?
- Which abstractions reduce repetition without hiding the effective assurance
  programme?
- Can modules and patterns remain deterministic, closed, and reviewable?
- How should diagnostics map generated IR back to source declarations?
- Should Pkl, CUE, or another typed frontend be used experimentally before a
  custom syntax?

### Method

1. Define a minimal abstract syntax directly over the Assurance IR.
2. Implement two experimental frontends:
   - a deliberately small custom textual DSL; and
   - one existing typed configuration frontend, such as Pkl, restricted to
     deterministic local evaluation.
3. Express the same Python, TypeScript, and Rust demonstrations in TOML and each
   frontend.
4. Require byte-identical canonical IR after normalization.
5. Conduct authoring studies using deliberately invalid cases:
   - sampled evidence supplied as proof;
   - theorem without subject correspondence;
   - duplicated or partial inventory;
   - unowned assumption;
   - conflicting policy ceiling; and
   - undeclared tool authority.
6. Measure authoring time, error localization, effective-program readability,
   and diff review quality.

### Deliverables

- language grammar or host-language schema;
- formatter;
- compiler to Assurance IR;
- effective-program renderer;
- source-mapped diagnostics;
- editor prototype; and
- frontend equivalence corpus.

### Exit criteria

- Equivalent frontends emit identical canonical IR and receipts.
- The DSL reduces repeated declarations in at least two real projects.
- Users can inspect the effective programme without evaluating imports
  mentally.
- Invalid evidence substitutions fail before tool execution.
- Frontend evaluation is deterministic and its dependency closure is bound.

### Stop condition

Do not adopt a custom language if it only changes syntax while leaving the same
runtime-only semantic errors and duplication.

## Workstream E: effects and capabilities

### Initial capability vocabulary

```text
Pure
Read[Closure]
Write[Ephemeral]
Write[Reviewed]
Execute[ToolIdentity]
Environment[Variable]
Network[Authority]
Clock
Randomness[Seed]
SecretRead[Identity]
HumanJudgment[Scope]
```

### Research questions

- Which capabilities are statically knowable at the assurance-program level?
- Which require operating-system sandbox enforcement?
- How are capabilities delegated through dependencies and adapters?
- Can effects form a useful partial order for policy?
- Can a build claim hermeticity without kernel-enforced network denial?
- How should observed effects differ from permitted effects?

### Method

1. Model current adapter and build operations with declared effects.
2. Encode organizational constraints such as “no reviewed writes” and “no
   network during reproducible build.”
3. Replay known defects involving ambient plugins, environment variables,
   hard-coded root writes, package lifecycle scripts, external source files,
   and executable modes.
4. Compare static rejection, sandbox enforcement, and post-execution detection.
5. Record both declared and observed authority in receipts.
6. Attempt capability smuggling through dependencies, subprocesses, symlinks,
   inherited descriptors, environment indirection, and generated scripts.

### Exit criteria

- At least two previously discovered real defects are prevented before the
  expensive evidence-producing operation.
- A mismatched declared/observed effect fails closed.
- The model distinguishes language-level effects from operating-system
  enforcement honestly.
- Ordinary pure evidence definitions do not require verbose capability
  annotations.

## Workstream F: uncertainty and notification quality

### Research questions

- What distinguishes an assumption, exclusion, uncertainty, contradiction,
  stale observation, and missing evidence?
- Can uncertainty have identity, owner, scope, expiry, consequence, and
  supporting evidence?
- How should uncertainty propagate and combine?
- Which changes deserve a notification rather than a graph update?
- Can claim-oriented reporting reduce fatigue without suppressing important
  weak signals?

### Method

1. Define a candidate uncertainty data model.
2. Annotate current demonstrations and selected external projects.
3. Construct realistic change scenarios that trigger many raw tool findings but
   affect few claims.
4. Compare two interfaces:
   - conventional tool-oriented alerts; and
   - Proofbound claim-oriented confidence changes.
5. Run structured studies with developers, security engineers, release owners,
   and auditors.
6. Test whether participants correctly identify:
   - affected claims;
   - load-bearing assumptions;
   - residual uncertainty;
   - required action;
   - publication consequence; and
   - unrelated findings that need no escalation.

### Measures

- time to correct impact assessment;
- missed critical consequence rate;
- false escalation rate;
- number of notifications presented;
- proportion dismissed without investigation;
- confidence calibration against known scenario truth; and
- ability to explain why a claim did or did not weaken.

### Exit criteria

- Claim-oriented reporting reduces irrelevant escalation without increasing
  missed critical consequences.
- Participants distinguish assumptions from evidence and exclusions.
- Every notification has a concrete claim, dependency path, and requested
  decision or action.

## Workstream G: native executable prototype

### Domain selection

The first native programme should be small, deterministic, security-relevant,
and rich enough to exercise the semantic model. Candidate domains are:

1. canonical binary parser and serializer;
2. authorization or policy evaluator;
3. deterministic protocol state machine;
4. append-only ledger transition function; or
5. capability-token validator.

A parser/serializer is the recommended first subject because its contracts are
precise and its artifact can be called from existing languages.

### Required language features

- algebraic data types and pattern matching;
- bounded integers and byte sequences;
- total pure functions;
- explicit partiality and error values;
- specifications with preconditions, postconditions, and invariants;
- executable examples and sampled properties;
- universal proof obligations;
- capability-restricted effects at foreign boundaries;
- deterministic module and dependency resolution; and
- reproducible artifact construction.

### Candidate parser claims

```text
decode(encode(value)) == value
encode(decode(bytes)) == canonical(bytes) when decode succeeds
successful decode consumes exactly the registered format
malformed input cannot construct an invalid value
all indexing is in bounds
decoding terminates within a registered resource function
```

### Verification architecture comparison

Prototype at least two routes:

- verification-condition generation discharged by an SMT backend; and
- proof terms or certificates checked by an existing small kernel.

Compare:

- trusted computing base;
- proof-checking independence;
- feedback latency;
- diagnostic quality;
- proof stability after refactoring;
- certificate size;
- unsupported-language surface; and
- source-to-artifact story.

### Exit criteria

- The prototype proves at least one universal functional property.
- It separately reports examples, sampled properties, and universal proof.
- Its proof result is independently checkable without rerunning proof search.
- Its artifact is deterministic or explicitly compiler-assumption-bound.
- A registered mutant is rejected by either the specification proof or an exact
  mutation witness.
- The emitted Assurance IR composes with an existing Python or TypeScript claim.

### Stop condition

Stop expanding the executable language if its assurance is no stronger than a
small Verus, Lean, or Dafny component integrated through existing Proofbound.

## Workstream H: source-to-artifact correspondence

### Strategies to compare

- verified compiler;
- proof-producing compiler;
- translation validation;
- deterministic compilation with explicit compiler assumptions;
- independent dual compilation;
- compilation to a smaller target such as WebAssembly;
- validated source translation to an existing verified backend; and
- reproducible builds plus byte-pinned toolchain provenance.

### Research questions

- What exactly can be established about generated machine code?
- Which compiler phases remain trusted?
- Can correspondence be checked per build rather than assumed globally?
- How do linker, runtime, standard library, build scripts, and platform enter
  the graph?
- What portable proof or observation can a standalone verifier check?

### Exit criteria

- Source proof and artifact correspondence remain distinct typed facts.
- Every trusted compiler component appears as an assumption or TCB identity.
- Changing compiler, linker, runtime, or build input invalidates the binding.
- A release report cannot shorten “source proved, compiler assumed” to an
  unqualified “artifact proved.”

## Workstream I: foreign and mixed-language boundaries

### Research questions

- How are foreign functions specified and identified?
- How do exceptions, callbacks, ownership, concurrency, and serialization cross
  the boundary?
- What evidence can support a foreign implementation's conformance?
- How does a component migrate from empirical correspondence to native proof?
- Can mixed graphs remain understandable to non-specialists?

### Method

1. Define a typed foreign-component contract.
2. Wrap one Python component and one TypeScript component.
3. Bind exact application tests, static analysis, package artifacts, and runtime
   assumptions to their contracts.
4. Replace one component with the native parser prototype.
5. Preserve the public claim while recording the stronger correspondence.
6. Test incompatible ABI, serialization, version, callback, and exception
   substitutions.

### Exit criteria

- Foreign components cannot claim native proof.
- Native and foreign evidence coexist in one canonical graph.
- Migration strengthens only affected claims.
- The report explains the remaining foreign assumptions without exposing
  backend implementation noise.

## Workstream J: kernel assurance and independent implementations

### Method

1. Track the kernel's lines of code, dependencies, unsafe code, parser surface,
   and cryptographic operations.
2. Maintain two implementations of critical validation and derivation logic.
3. Generate well-formed and adversarial IR corpora.
4. Differentially test both implementations.
5. Mutation-test status derivation, canonicalization, and identity joins.
6. Formally specify or mechanize the smallest high-impact inference rules.
7. Produce a self-assurance case for the kernel without treating that case as a
   substitute for independent review.

### Exit criteria

- No application adapter dependency enters the standalone checker.
- Two implementations agree over generated and adversarial corpora.
- Every accepted strong status has a traceable derivation tree.
- Unknown schemas, duplicate identities, aliasing, omitted fields, and
  inconsistent canonical forms fail closed.
- Kernel complexity remains within a separately reviewable budget established
  before native-language expansion.

## Experimental programme

Each item below should be promoted into `docs/experiments/` as a preregistered
experiment before execution.

| Experiment | Hypotheses | Subject | Primary result |
|---|---|---|---|
| EXP-LANG-001 Assurance IR extraction | H1, H2 | Current Python, TypeScript, Rust, Lean, Kani, and release fixtures | Semantic parity and core/backend field boundary |
| EXP-LANG-002 Generated evidence algebra | H2 | Property-generated valid and adversarial evidence graphs | Producer/verifier agreement and forbidden coercions |
| EXP-LANG-003 Invalidation precision | H3 | Controlled changes across demos and external trials | Zero false retention and measured re-execution reduction |
| EXP-LANG-004 Dual frontend equivalence | H4 | One Python, one TypeScript, and one Rust project in TOML and DSL | Byte-identical Assurance IR and authoring comparison |
| EXP-LANG-005 Effect-checked replay | H5 | Mutation and distribution routes with known attack fixtures | Static prevention and observed-effect parity |
| EXP-LANG-006 Notification comparison | H6 | Synthetic incident/change scenarios with practitioners | Impact accuracy, time, and alert-volume comparison |
| EXP-LANG-007 Native parser | H7 | Small canonical binary format | Independently checked functional proof and artifact |
| EXP-LANG-008 Mixed-language migration | H8 | Python or TypeScript application calling native parser | Honest strengthening across the foreign boundary |
| EXP-LANG-009 Specification falsifiers | H2, H7 | Vacuous and inconsistent contracts | Detection of always-success, empty-domain, and weak-postcondition specifications |
| EXP-LANG-010 Kernel differential validation | H1, H2 | Generated canonical IR corpus | Agreement between independent implementations |

## Evaluation corpus

The corpus should include both controlled and external subjects.

### Controlled subjects

- Python inventory-service demonstration;
- TypeScript codec demonstration;
- Rust allowance/Aeneas demonstration;
- Kani bounded-check fixtures;
- Lean theorem and artifact-certificate fixtures;
- mutation, transcription, and release conformance corpora; and
- the proposed native parser.

### External subjects

Maintain variety rather than selecting several projects from one organization
or ecosystem style:

- Python CLI/library project;
- Python data-model or functional library;
- Python network/client project;
- TypeScript library;
- TypeScript application or build-tool project;
- Rust systems library;
- one Verus-verified project if its build and licensing permit; and
- one project with a nontrivial packaging or foreign-runtime boundary.

External repositories remain outside Proofbound history. Record commit
identity, toolchain, local changes, registered claim, outcome, and discovered
product defect in experiment journals.

## Common measurements

### Soundness indicators

- false evidence acceptance count;
- stale-cache acceptance count;
- producer/verifier disagreement count;
- forbidden evidence coercion count;
- missing dependency or assumption join count; and
- proof or artifact substitution acceptance count.

All target zero in the registered corpus.

### Complexity indicators

- Assurance IR variants and required fields;
- kernel lines of code and dependency count;
- number of backend-name conditionals in generic logic;
- proof certificate size;
- frontend-to-IR implementation size;
- adapter implementation size before and after shared protocols; and
- schema/version migration count.

### Usability indicators

- time to author a correct claim;
- time to diagnose a deliberately invalid programme;
- repeated lines across projects;
- effective-program comprehension accuracy;
- incremental feedback latency; and
- proportion of users who correctly distinguish sampled, bounded, source
  proved, and artifact-bound results.

### Operational indicators

- fresh and incremental execution time;
- cache hit rate with semantic equivalence;
- graph fraction invalidated per change class;
- portable receipt size;
- independent verification time; and
- release reproduction success across environments.

## Sequencing and gates

The phases are dependency-ordered research gates, not calendar promises.

### Gate 0: baseline

Before new implementation:

- freeze representative current receipts and graph outputs;
- enumerate current evidence families and trust boundaries;
- record current kernel and adapter complexity;
- preserve known security regressions as adversarial fixtures; and
- preregister EXP-LANG-001 through EXP-LANG-003.

### Gate 1: shared semantics

Complete Workstreams A, B, and C.

Proceed only if the IR is smaller and more stable than the combined backend
schemas, derivation is explicit, and invalidation has zero known false
retention.

### Gate 2: authoring and effects

Complete Workstreams D and E.

Proceed only if the DSL catches meaningful errors before execution, compiles
equivalently to existing manifests, and the effect model prevents demonstrated
defects without unacceptable ceremony.

### Gate 3: product value

Complete Workstream F.

Proceed only if claim-oriented uncertainty improves impact assessment or
notification quality in measured studies. A technically elegant language that
does not improve decisions is not sufficient.

### Gate 4: native feasibility

Complete Workstreams G and H.

Proceed only if the native prototype yields a stronger, independently checkable
source/artifact story than a comparable existing-language integration, with a
bounded trusted kernel.

### Gate 5: adoption bridge

Complete Workstreams I and J.

Proceed toward a language specification only if mixed-language migration is
honest and usable, independent implementations agree, and the bridge remains a
first-class supported product.

## Decision rules

### Continue toward a native language when

- the same IR supports existing and native subjects;
- the evidence algebra eliminates real classes of invalid states;
- effects prevent demonstrated trust-boundary defects;
- the checker remains backend-independent and reviewable;
- source-to-artifact correspondence is explicit and useful;
- a native component materially strengthens a mixed application; and
- user studies show better decisions rather than merely different syntax.

### Stop at an assurance DSL when

- typed authoring and shared semantics provide clear value;
- native executable code adds large compiler or ecosystem costs;
- existing verified languages provide equivalent native assurance; or
- foreign boundaries dominate realistic systems regardless of implementation
  language.

### Remain a framework when

- no compact evidence algebra survives cross-ecosystem use;
- IR evolution repeatedly follows individual tool output formats;
- the independent checker grows with every backend;
- selective invalidation cannot be both sound and narrow; or
- users do not understand or act on the richer assurance model.

## Research governance

- Promote each experiment from this plan into a preregistered experiment file
  with pass criteria, falsifiers, fixtures, and expected divergence classes.
- Keep raw execution journals and tool identities with the experiment.
- Record semantic changes as ADRs only after an experiment closes.
- Version the Assurance IR independently from authoring frontends.
- Require independent review for changes to evidence strength or derivation.
- Treat null results and stop decisions as successful research outcomes.
- Do not describe a prototype feature as supported until producer, independent
  verifier, public schema, adversarial corpus, and documentation agree.

## Initial backlog

The first implementation sequence should be:

1. Create the current semantic-field inventory.
2. Freeze golden outputs for the Python, TypeScript, Rust/Aeneas, Kani, Lean,
   mutation, and distribution routes.
3. Draft Assurance IR `/1` with no new product behavior.
4. Write a second minimal decoder and canonicalizer.
5. Encode the evidence algebra and status derivations explicitly.
6. Generate valid and adversarial IR graphs.
7. Run invalidation experiments over known cache and closure attacks.
8. Prototype the assurance-only DSL over the stable subset.
9. Add effects to mutation replay and reproducible packaging.
10. Conduct the first notification-quality study.
11. Select and preregister the native parser experiment.
12. Decide at Gate 3 whether native executable work remains justified.

## Current recommendation

Start with EXP-LANG-001: Assurance IR extraction. It is useful under every
possible strategic outcome. It should simplify the current system, expose
whether a language-independent semantic core truly exists, improve independent
verification, and provide the only sound foundation on which either a typed DSL
or native executable language could be built.
