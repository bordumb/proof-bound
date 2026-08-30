# Specification 0001: Proofbound and Proof-Driven Development

**Status:** Initial implementation specification

**Version:** 0.3.0

**Date:** 2026-08-30

**Project:** Proofbound

**Process:** Proof-Driven Development (PDD)

### Revision history

- **0.1.0** — initial draft.
- **0.3.0** — adoption and independence revisions: adoption tiers and
  brownfield/greenfield workflows (§4.3–4.4); independent receipt verifier
  (§10.4); premise nodes with policy-gated discharge (§6.1–6.3, §8.1);
  assurance-regression classification and approval records (§12.2, §18.1);
  JSON subprocess adapter protocol (§10.2); mandatory not-proved/out-of-scope
  reporting (§12.2, §18.2); aggregate-score ban (§3.2); reference assessments
  pinned to audited commits (§15).
- **0.2.0** — review revisions: faceted status derivation (§6.3); expanded
  translation-unit schema and the manifest-inversion requirement (§11.3);
  trusted transcription named as a degraded binding (§7.1.1); evaluation and
  binding modes on evidence records and a `mutation-witness` kind (§5);
  extract-vs-redesign grading of reference machinery (§15); verify-vs-update
  CI policy (§18.1); evidence caching and cost budgets (§16.2–16.3);
  `check`/`update` contract (§12.2); closure granularity floor (§11.4);
  milestone reordering to follow the extraction rule, including a reference
  adoption pilot (§20).

## 1. Executive summary

Proofbound is a framework for **proof-driven development**: software development
in which important claims about a system are registered explicitly and must be
classified by machine-checkable evidence.

The framework does not pretend that every property of a practical system can be
proved. Instead, it makes the boundary visible. Every registered claim must be
reported as one of:

- proved by a named theorem;
- linked to shipping code by a checked refinement;
- bounded-checked by a model checker;
- independently cross-checked;
- empirically tested;
- dependent on an explicit assumption; or
- open and therefore not established.

The central promise is:

> Every important claim is proved, explicitly assumed, tested, or visibly open.

Unit tests remain useful, but they no longer carry more meaning than their
coverage warrants. A named axiom is not silently presented as a proof. A model
proved in Lean is not presented as a property of production code unless a
registered bridge links the two. A successful bounded Kani harness is not
presented as an unbounded theorem. Proofbound compiles these distinctions into
an assurance graph and fails closed when a claimed status is unsupported.

The initial implementation generalizes two working patterns, each graded for
maturity in Section 15:

1. **Artifact soundness**, as used in Matrix Math: an untrusted producer emits
   canonical bytes; Rust independently checks them; Lean independently decodes
   the same bytes and proves that acceptance implies the mathematical claim.
2. **Source refinement**, as used in Auths Proof: a small pure Rust kernel is
   extracted by Charon, translated by Aeneas, and related in Lean to richer
   handwritten semantics; Kani separately supplies bounded implementation
   evidence.

Proofbound standardizes the machinery around these patterns without generating
or sharing domain semantics between supposedly independent implementations.
Where the reference implementations are themselves partial or compromised,
Section 15 says so; a framework whose thesis is honest evidence does not
launder the maturity of its own sources.

## 2. Product language

### 2.1 Name

- **Proofbound** is the project and framework.
- **Proof-Driven Development** is the engineering process.
- **Compiled assurance** describes the resulting artifact, but is not used as
  an acronym or product name.

### 2.2 Tagline

> Make your software's claims compile.

### 2.3 Intended users

The first users are engineers building polyglot systems with claims that matter
more than ordinary unit-test confidence, including:

- security and authorization kernels;
- numerical and scientific checkers;
- canonical encoders and protocol decoders;
- financial or resource-accounting state machines;
- compilers and translators;
- deterministic workflow engines; and
- publication or certification pipelines.

Proofbound is not restricted to Python, Rust, and Lean. Those languages form
the first supported vertical because they exercise orchestration, production
implementation, bounded model checking, source translation, and theorem proving.

## 3. Goals and non-goals

### 3.1 Goals

Proofbound MUST:

1. Register important software claims with stable identities.
2. Bind each claim to exact source, binary, artifact, schema, and toolchain
   identities as applicable.
3. Record the transitive assumptions and trusted computing base of every proof.
4. Distinguish theorem proof, code refinement, bounded checking, differential
   evidence, tests, and assumptions.
5. Support both artifact-oriented and source-oriented assurance patterns.
6. Make translation units, proof declarations, model-checking harnesses, source
   closures, and policies manifest-driven rather than hard-coded, in the strong
   sense defined by Section 11.3: manifests drive tool invocation; they are not
   cross-checks of constants in orchestration source.
7. Produce human-readable and machine-readable explanations of why a claim does
   or does not hold.
8. Fail closed on malformed manifests, missing evidence, drift, undeclared
   assumptions, ambiguous identities, or stale generated output.
9. Permit explicit hypotheses where complete proof is not yet practical.
10. Make remaining gaps visible in the normal build rather than in a detached
    audit document.
11. Provide reusable tooling applicable to arbitrary source folders.
12. Provide a `demo/` tree containing complete, understandable verticals.

### 3.2 Non-goals

Proofbound MUST NOT:

- claim that tests prove universal properties;
- claim that a handwritten Lean model describes shipping code without a bridge;
- claim that bounded model checking establishes an unbounded theorem;
- generate both sides of an independence claim from one semantic implementation;
- hide project axioms behind generic labels such as `trusted`;
- prove network providers, operating systems, hardware, cryptographic libraries,
  or human-entered evidence correct merely because they are named in a manifest;
- require all application code to be written in a proof assistant;
- act as a universal semantic framework for unrelated application domains;
- publish aggregate assurance scores such as "87% verified" — a scalar
  percentage launders exactly the distinctions this framework exists to keep;
  status is reported as facets and enumerated assumptions, never as a single
  number; or
- replace domain-specific threat models, specifications, or review.

## 4. Proof-driven development

Proof-driven development changes the order of implementation. The unit of work
is not merely a function or test; it is a **claim closure**.

### 4.1 Workflow

For each material feature:

1. State the claim in domain language.
2. Identify the exact production subject to which it applies.
3. Define the formal meaning of inputs, outputs, failure, and resource limits.
4. Choose an assurance pattern from Section 7.
5. Register assumptions and the intended trust profile before implementation.
6. Implement a small deterministic semantic kernel or canonical artifact
   boundary.
7. Build the proof, refinement, bounded harness, independent checker, and tests
   appropriate to the claim.
8. Compile the assurance graph.
9. Inspect all residual assumptions and open obligations.
10. Publish only the claim language admitted by the compiled graph.

The intended developer loop is:

```text
+-------------------------------------------------------------------+
| proofbound status                                                 |
+----------------------+----------------------+---------------------+
| Claim                | Status               | Boundary            |
+----------------------+----------------------+---------------------+
| transfer.conserves   | PROVED · REFINED     | Rust kernel         |
| request.canonical    | PROVED · ART-BOUND   | published bytes     |
| signature.valid      | ASSUMED              | crypto provider     |
| api.exactly-once     | OPEN                 | effectful workflow  |
+----------------------+----------------------+---------------------+
| 2 proved · 1 assumed · 1 open · publication policy: BLOCKED      |
+-------------------------------------------------------------------+
```

### 4.2 Claim closure

A claim is closed only when all of the following are available and valid:

- a stable claim identifier;
- exact human and formal statements;
- a subject identity;
- an evidence path;
- a transitive dependency graph;
- a transitive assumption set;
- a trust profile;
- a source and toolchain closure;
- an assurance policy verdict; and
- a reproducible receipt.

A proof theorem without a production subject is a model theorem, not a shipping
claim. A production artifact without a meaning theorem is checked data, not a
proved claim.

### 4.3 Adoption tiers

Full proof-driven development is expert work, and no orchestrator changes
that. What Proofbound can change is how much of the value is available before
the expert work begins. Adoption is therefore tiered, and the tiers are
first-class: a project declares its tier in `proofbound.toml`, fail-closed
enforcement applies to the tiers the project has opted into, and status
language never exceeds what the tier can support.

| Tier | Adds | Requires | Strongest status |
|---|---|---|---|
| **0** | Claim ledger: registered claims, explicit assumptions, existing tests bound as evidence | The `proofbound` CLI only — no new toolchains | `TESTED` / `ASSUMED` / `OPEN` |
| **1** | Bounded model checking, independent and exhaustive checks | Kani (or equivalent) | `BOUNDED_CHECKED` |
| **2** | Model theorems and the compiled axiom audit | Lean toolchain | `PROVED` + `MODEL_ONLY` |
| **3** | Source refinement and artifact binding | Charon/Aeneas, digest theorems | `PROVED` + `REFINED` / `ARTIFACT_BOUND` |

Tier 0 is deliberately valuable on its own: most teams have never enumerated
their load-bearing claims, and an honest board of `TESTED`, `ASSUMED`, and
`OPEN` over an existing test suite is a real deliverable, not a teaser.
`init` scaffolds Tier 0 (§12.2), and a Tier 0 project MUST be able to reach a
green `status` in one working session without installing a proof assistant.

Tiers are per-project floor, per-claim ceiling: a Tier 3 project may hold
Tier 0 claims, but a claim may not cite evidence from a tier the project has
not opted into. Moving a claim up a tier is the normal growth path and never
requires restating its identity.

### 4.4 Greenfield and brownfield workflows

**Greenfield** projects follow the workflow of Section 4.1: claims are
registered before implementation, and the first commit of a feature includes
its claim manifest.

**Brownfield** projects invert the entry: inventory what already exists.

1. Enumerate the claims the system already silently makes.
2. Register them at Tier 0, binding existing tests as `example-test` and
   `property-test` evidence.
3. Register what the team already knows it is trusting as explicit
   assumptions — this step usually surfaces the first surprises.
4. Let `status` show the honest board: mostly `TESTED`, some `ASSUMED`,
   some `OPEN`.
5. Promote individual claims up the tiers where the value justifies the
   proof-engineering cost.

Both workflows converge on the same manifests and the same graph; they differ
only in entry order.

## 5. Evidence taxonomy

Proofbound MUST keep evidence kinds distinct. A claim MAY have several evidence
kinds simultaneously.

| Evidence kind | Meaning |
|---|---|
| `theorem` | A proof assistant kernel accepted the named theorem. |
| `artifact-soundness` | A theorem links acceptance of exact canonical bytes to a formal meaning. |
| `source-refinement` | Translated or otherwise linked production code refines formal semantics under stated representation premises. |
| `bounded-check` | A bounded model checker established the property over the registered finite domain. |
| `independent-check` | A deliberately independent implementation agreed on registered vectors or artifacts. |
| `exhaustive-check` | Every member of an explicitly finite registered domain was evaluated. |
| `property-test` | Generated examples exercised a property; this is empirical evidence. |
| `example-test` | Named test cases passed. |
| `mutation-witness` | A registered mutation of the subject was shown to violate a registered check. The strongest form is a compiled proof term witnessing the violation; the weakest is a registered, deliberately failing test. |
| `review` | A human review attestation exists for a precisely scoped surface. |
| `assumption` | The claim depends on an explicit hypothesis or external premise. |
| `open` | Required evidence is absent or incomplete. |

Two qualifiers keep the strong kinds honest:

- **Evaluation mode.** Every `theorem` and `artifact-soundness` record MUST
  state how the proof was checked: `kernel` (ordinary elaboration, `decide`)
  or `native` (`native_decide` or compiled evaluation). Native evaluation
  enlarges the trusted computing base (§9.5) and must be visible at the
  evidence level, not only in the trust profile.
- **Binding mode.** Every `artifact-soundness` record MUST state its binding:
  `bytes-in-theorem`, `digest-theorem`, or `external-round-trip`
  (Section 7.1.1). The three are not interchangeable and the graph never
  conflates them.

The status vocabulary MUST NOT compress these into a single scalar such as
`verified`. Summary status is the three-facet composition defined in
Section 6.3. Flat labels such as `PROVED_WITH_ASSUMPTIONS` and
`TRANSLATED_AND_REFINED` are display aliases for facet combinations, and
detailed evidence remains visible beneath every summary.

## 6. The assurance graph

### 6.1 Node kinds

The compiled graph contains typed nodes:

- `claim`;
- `theorem`;
- `subject`;
- `artifact`;
- `source-closure`;
- `translation-unit`;
- `model-check-unit`;
- `test-suite`;
- `assumption`;
- `premise`;
- `toolchain`;
- `tcb-component`;
- `review`; and
- `policy`.

### 6.2 Edge kinds

Edges have explicit semantics:

- `proves`;
- `refines`;
- `decodes`;
- `checks`;
- `generated-from`;
- `depends-on`;
- `assumes`;
- `discharged-by`;
- `cross-checks`;
- `covers-bounded-domain`;
- `binds-digest`;
- `reviewed-by`; and
- `admitted-by-policy`.

Unknown node or edge kinds MUST be rejected. Cycles are allowed only for
declared mutual theorem dependencies internal to one proof environment; cycles
in artifact generation or provenance are invalid.

### 6.3 Status derivation

Status is derived, never manually asserted, as a function of the validated
evidence set and the claim's policy. This section is normative: it is the
core algorithm of the product, and no adapter, plugin, or display layer may
substitute its own mapping.

#### 6.3.1 Facets

A claim's summary status is a composition of three orthogonal facets rather
than a single scalar:

1. **Formal facet** — the strongest policy-admitted formal standing:
   `PROVED`, `BOUNDED_CHECKED`, `TESTED`, `OPEN`, or `INVALID`.
2. **Linkage facet** — how the formal object is connected to the shipping
   subject: `REFINED`, `ARTIFACT_BOUND`, `TRANSCRIBED`, or `MODEL_ONLY`.
3. **Assumption facet** — `NONE`, or `ASSUMED` with the enumerated assumption
   set (project axioms, representation premises, external premises).

Display aliases from earlier drafts remain valid shorthand:
`PROVED_WITH_ASSUMPTIONS` means `PROVED` + `ASSUMED`;
`TRANSLATED_AND_REFINED` means `PROVED` + `REFINED`.

#### 6.3.2 Derivation rules

Formal facet, from the validated evidence set:

| Validated evidence present | Formal facet |
|---|---|
| `theorem` passing the compiled axiom audit under the claim's policy | `PROVED` |
| no admissible theorem; valid `bounded-check` over a registered domain | `BOUNDED_CHECKED` |
| only empirical kinds (`property-test`, `example-test`, `independent-check`, `mutation-witness` without proof-term witnesses) | `TESTED` |
| none of the above | `OPEN` |
| any cited record missing, failed, drifted, unregistered, or ambiguous | `INVALID` |

Linkage facet, from the subject-binding evidence:

| Binding evidence | Linkage facet |
|---|---|
| `source-refinement` with a named refinement theorem and registered representation premises | `REFINED` |
| `artifact-soundness` with binding `bytes-in-theorem` or `digest-theorem` | `ARTIFACT_BOUND` |
| `artifact-soundness` with binding `external-round-trip` (§7.1.1) | `TRANSCRIBED` |
| no subject binding | `MODEL_ONLY` |

Additional rules:

- **Premises are first-class and undischarged by default.** Every hypothesis
  on a registered theorem — validated-constructor invariants, borrowed-view
  well-formedness, bounded-carrier conditions — is a `premise` node attached
  to that theorem. A premise counts in the assumption facet **unless** it is
  discharged: a `discharged-by` edge connects it to another policy-admitted
  theorem (one that itself passes the compiled axiom audit under the same
  claim policy) proving the premise holds for the claim's registered inputs —
  for example, a decoder theorem proving every decoded value satisfies the
  bounded-carrier condition. The absence of a discharge edge always means
  undischarged; forgetting an edge can only weaken a status, never
  strengthen it. Discharge is never silent: a discharged premise remains
  visible in claim output with its discharging theorem, and a discharge
  scoped to particular flows must state that scope. Premises are mandatory
  for `REFINED` linkage; a refined claim with undischarged premises renders
  `PROVED` + `REFINED` + `ASSUMED`, and that is the honest rendering, not a
  demotion. Discharge is the only mechanism that removes a premise from the
  assumption facet, and it is policy-gated precisely so it cannot become a
  status-upgrade backdoor.
- **Precedence.** The formal facet takes the strongest evidence the policy
  admits. Weaker evidence is retained and displayed beneath the summary; it
  is never discarded or double-counted.
- **`INVALID` semantics.** `INVALID` is both a reportable status and a build
  failure: it renders in `status` output so the operator can see which claim
  broke and why, and the presence of any `INVALID` claim causes a nonzero
  exit. `INVALID` overrides all other facets.
- **Bounded language.** A `BOUNDED_CHECKED` claim must state its registered
  finite domain in its public claim language; no unbounded language is
  emitted for bounded evidence.
- **Exhaustiveness.** `exhaustive-check` over a registered finite domain
  MAY be admitted as `PROVED` only when the policy explicitly says so and
  the domain registration is itself part of the claim closure; otherwise it
  is strong `TESTED` evidence.

#### 6.3.3 Example

```text
Lean theorem ──proves───────────────┐
                                    v
Generated decoder theorem ──binds── Claim
                                    ^
Shipping Rust function ──refines────┘
                 |
                 +──assumes──> valid-constructor premise
```

The resulting claim is `PROVED` + `REFINED` + `ASSUMED` (display alias:
`PROVED_WITH_ASSUMPTIONS`), with the source refinement and the named
constructor premise visible. Removing or changing any supporting node
invalidates the receipt.

## 7. Supported assurance patterns

### 7.1 Pattern A: canonical artifact soundness

This pattern is appropriate when untrusted or heuristic code can emit a compact
certificate that is cheaper to check than to discover.

```text
Untrusted producer (Python/Rust/other)
                  |
                  v
          canonical artifact bytes
             /                 \
            v                   v
 independent diagnostic     Lean byte decoder
   and exact checker              |
            |                     v
            |                Boolean checker
            |                     |
            +--- cross-check -----+
                                  v
                   acceptance-implies-meaning theorem
                                  |
                                  v
                         artifact-bound claim
```

Requirements:

- canonical, bounded, versioned bytes;
- rejection of trailing, oversized, ambiguous, or non-canonical inputs;
- an independently implemented Lean decoder inside the theorem boundary;
- a theorem connecting decoder/checker acceptance to domain meaning;
- a digest theorem connecting the published bytes to the claim — digest
  binding is the **default**, not an optional refinement;
- an independent diagnostic checker where feasible; and
- explicit separation between search/production and trusted checking.

Full byte binding has real cost: embedding published bytes in the theorem
generally requires native evaluation (which enlarges the TCB, §9.5) and grows
generated modules. That cost is recorded in the TCB ledger and the evidence
evaluation mode; it is not a reason to silently weaken the binding.

The framework MAY generate envelope grammar, bounded parser scaffolding, error
codes, and module boilerplate. It MUST NOT generate both independent semantic
checkers from one implementation and then describe their agreement as
independent corroboration.

#### 7.1.1 Degraded variant: trusted transcription

A common weaker variant transcribes orchestrator-decoded values into typed
Lean literals and enforces the byte binding with an untrusted re-encoder
outside the theorem boundary. The reference reality is instructive: Matrix
Math's rank track does exactly this — its per-certificate theorems run over
Rust-transcribed literals, with byte identity enforced by a Rust round-trip
re-encoder — and even its ω track uses digest-conjoined theorems in only a
minority of committed modules. The requirement list above is therefore an
aspiration the reference only partially meets, and Proofbound names the
weaker shape rather than pretending it is the strong one.

Proofbound admits trusted transcription but never conflates it with artifact
soundness:

- its `artifact-soundness` evidence MUST carry binding mode
  `external-round-trip`;
- its linkage facet is `TRANSCRIBED`, never `ARTIFACT_BOUND` (§6.3.2);
- the transcriber and re-encoder join the claim's TCB inventory as
  `tcb-component` nodes; and
- profile `artifact-bound` (§9.3) rejects it.

### 7.2 Pattern B: translated source refinement

This pattern is appropriate when a small pure production kernel is itself the
subject of the claim.

```text
Validated production inputs
          |
          v
    pure Rust kernel  <------ Kani bounded harnesses
          |
       Charon
          |
         LLBC
          |
       Aeneas
          |
 generated Lean function
          |
  handwritten adapters and refinement lemmas
          |
 rich handwritten Lean semantics
          |
      public claim
```

Requirements:

- a deterministic, effect-free, bounded kernel;
- exact translation-unit source and symbol closure;
- pinned Charon and Aeneas versions;
- deterministic translation reproduced twice;
- generated Lean quarantined from handwritten semantics;
- no transitive `sorry` or undeclared generated axiom in public claims;
- explicit representation premises for validated constructors and borrowed
  views, registered as premise nodes and discharged or displayed per
  Section 6.3.2;
- field-for-field or decision-adequate adapters with stated strength; and
- named refinement theorems connecting translated output to rich semantics.

Kani is complementary bounded evidence. It is not the Rust-to-Lean refinement
bridge.

### 7.3 Pattern C: shared declarative algebra

A small finite algebra MAY be declared once and used to generate Rust and Lean
implementations when the claim is conformance to that shared declaration rather
than independence between implementations.

This pattern MUST be marked as common-origin evidence. It requires:

- a canonical algebra contract;
- generated-file hashes;
- exhaustive vectors for the finite domain;
- bounded Kani harnesses where applicable; and
- a theorem about the generated Lean algebra.

It MUST NOT be marketed as independent Rust/Lean agreement because both derive
from the same semantic source.

### 7.4 Pattern composition

A project MAY combine patterns. For example, translated Rust may validate a
canonical artifact whose mathematical meaning is separately proved by an
artifact-soundness theorem. The assurance graph must preserve each boundary.

## 8. Assumptions and known gaps

### 8.1 Assumptions are first-class artifacts

Every assumption has:

- stable ID;
- exact statement;
- category;
- owner;
- rationale;
- scope;
- affected claims;
- review evidence;
- falsification or discharge plan;
- source citation where applicable; and
- status.

Categories include:

- `mathematical-hypothesis`;
- `representation-premise`;
- `translator-tcb`;
- `compiler-tcb`;
- `runtime-environment`;
- `external-provider`;
- `cryptographic-library`;
- `human-attestation`; and
- `native-evaluation`.

Representation premises deserve emphasis because they are structural, not
incidental: source translation erases validated constructors and borrowed
views into raw carriers, so every realistic refinement theorem takes validity
structures as explicit hypotheses. These hypotheses are registered `premise`
nodes of category `representation-premise`, are mandatory for `REFINED`
linkage, and render in the assumption facet unless discharged by a
policy-admitted theorem (§6.3.2). The assumption record's "falsification or
discharge plan" field is where an undischarged premise names the theorem that
would discharge it; landing that theorem and adding the `discharged-by` edge
is the normal way a claim's assumption burden shrinks over time. A framework
that hid undischarged premises would be reporting a stronger claim than the
theorem states.

### 8.2 Lean axiom audit

For every registered Lean theorem, Proofbound MUST compile an axiom audit from
the elaborated environment. Source-text search is insufficient. The audit must:

- record the theorem's fully qualified declaration name;
- hash its elaborated statement;
- enumerate transitive axioms;
- distinguish standard Lean/Mathlib axioms from project axioms;
- compare the set against the claim's policy; and
- reject `sorryAx`, undeclared project axioms, or stale declaration identities.

The compiled audit applies to **all** claim-bearing modules, including
generated result-local modules; gating generated modules by text-parsing
`#print axioms` output while the claim inventory uses the compiled audit is
exactly the two-mechanism drift the reference implementations exhibit, and it
is prohibited here.

Translator-generated placeholder axioms MAY exist only in quarantined,
uncompiled templates, declared per file with exact counts (§11.3). A public
claim must depend on transparent compiled replacements or list the axiom
explicitly.

### 8.3 Known gaps

An open obligation is not an assumption unless the project deliberately adopts
it as a premise. Proofbound must distinguish:

- **assumed:** admitted, named, and included in the claim language;
- **open:** not established and therefore blocks stronger claim language; and
- **out of scope:** explicitly excluded from the registered claim.

## 9. Trust profiles

Policies are named trust profiles rather than informal release conventions.
The initial built-in profiles are:

### 9.1 `kernel`

- Named theorem compiles.
- No project axioms.
- No `sorryAx`.
- Only configured foundational proof-system axioms are allowed.
- Evaluation mode is `kernel`.

### 9.2 `kernel-with-assumptions`

- Named theorem compiles.
- Every project axiom is explicitly registered and allowlisted.
- Claim output enumerates those assumptions prominently.

### 9.3 `artifact-bound`

- Satisfies `kernel` or `kernel-with-assumptions`.
- The theorem binds canonical payload bytes, schema, literal claim, and digest.
- Binding mode is `bytes-in-theorem` or `digest-theorem`;
  `external-round-trip` binding does not qualify (§7.1.1).
- Re-encoding and trailing-byte checks pass.

### 9.4 `source-refined`

- Translation is deterministic and pinned.
- Generated code compiles without undeclared axioms.
- A named theorem connects the translated production function to the semantic
  model under registered representation premises.

### 9.5 `native-evaluated`

- A certificate-specific native evaluation premise is registered.
- The policy states whether exactly one such premise is required.
- The native implementation and complete TCB inventory are bound.
- Every admitted theorem's evidence record carries evaluation mode `native`.

### 9.6 `bounded`

- The bounded domain is explicit.
- All harnesses are inventoried.
- Solver/tool version, unwind bounds, assumptions, and results are recorded.
- No unbounded claim is emitted.

Projects MAY define stricter profiles. They MUST NOT redefine the meaning of a
built-in profile.

## 10. Framework architecture

```text
+-------------------- Project-owned semantics ---------------------+
| source kernels | schemas | Lean models | claim manifests | tests |
+-------------------------------+-----------------------------------+
                                |
                                v
+----------------------- Proofbound adapters -----------------------+
| Lean | Charon/Aeneas | Kani | canonical artifact | tests | review|
+-------------------------------+-----------------------------------+
                                |
                                v
+------------------------- Evidence store --------------------------+
| content-addressed records | source closures | toolchain receipts  |
+-------------------------------+-----------------------------------+
                                |
                                v
+------------------------ Assurance compiler -----------------------+
| graph validation | axiom audit | drift checks | policy evaluation |
+-------------------------------+-----------------------------------+
                                |
                +---------------+---------------+
                v                               v
       machine-readable receipt         human status/report
```

### 10.1 Core

The core owns:

- canonical manifest schemas;
- typed IDs and digests;
- graph construction and validation;
- status derivation;
- policy evaluation;
- evidence receipt schemas;
- stable errors; and
- content-addressed storage interfaces.

The core does not own domain theorem statements or production semantics.

### 10.2 Adapters

Adapters turn external tool results into canonical evidence records. An adapter
must declare:

- tool identity and version;
- exact inputs and outputs;
- supported evidence kind;
- parser and failure behavior;
- reproducibility command;
- resource limits;
- source closure; and
- residual assumptions.

Initial adapters:

- `lean`;
- `charon-aeneas`;
- `kani`;
- `rust-test`;
- `python-test`;
- `canonical-artifact`;
- `source-closure`;
- `independent-check`; and
- `human-review`.

Adapters MUST fail if a configured target is silently skipped. Kani harnesses,
Lean declarations, translation symbols, and tests must be inventoried, and
ungated discoveries must fail the build. Inventories are derived from tool
metadata, not source-text scanning (§17).

Adapters communicate with the orchestrator over a versioned JSON subprocess
protocol: requests and responses are schema-validated canonical JSON on
stdin/stdout (`schemas/adapter-protocol.schema.json`), and evidence is
returned as canonical receipt records. An adapter is therefore any process in
any language that speaks the protocol — future language verticals do not link
against the Rust core, and no adapter couples to a Rust ABI.

### 10.3 Project plugins

A project plugin packages domain-specific templates and checks without entering
the framework core. Examples include a numerical-certificate plugin or an
authorization-kernel plugin. Plugins may declare new evidence schemas but may
not override built-in evidence meanings.

### 10.4 Independent receipt verifier

The orchestrator both runs tools and computes statuses; a bug there could
falsely report success. Proofbound therefore ships `proofbound-verify`: a
separate minimal crate — not a subcommand, so it shares no code with the
orchestrator — that is the portable trust boundary for CI, releases, and
third-party reviewers.

`proofbound-verify`:

- executes no external tools;
- reads an assurance receipt set and compiled graph;
- validates schemas, digests, and closure membership;
- recomputes the claim graph and status facets from the receipts; and
- rejects unsupported evidence kinds, unknown schemas, and any status
  stronger than its recomputation derives.

Its trust boundary is stated, not implied: `proofbound-verify` certifies that
the reported statuses are **receipt-consistent** — that the graph and facets
follow from the recorded evidence under Section 6.3. It cannot attest that
Lean, Kani, or any other tool actually ran honestly; that remains bound by
the receipts' tool identities, closures, and reproduction commands. Its
output language is capped accordingly and never says "verified" without the
qualifier.

The verifier necessarily reimplements the Section 6.3 derivation. That
duplication is a deliberate independent-check, held to the framework's own
standard: both implementations derive from this specification, share no
source, and are cross-checked against a registered corpus of synthetic
graphs — including graphs constructed to tempt status upgrades. Divergence
between the two implementations fails CI.

## 11. Manifest model

### 11.1 Project manifest

Root `proofbound.toml`:

```toml
schema = "proofbound-project/1"
project = "allowance-demo"

[source]
semantic = ["rust/kernel/**", "lean/Allowance/**", "claims/**"]
runner = ["python/**", "Cargo.lock", "lake-manifest.json"]
presentation = ["demo/**", "docs/**"]

[toolchains]
rust = "rust-toolchain.toml"
lean = "lean-toolchain"
python = ".python-version"
translation = "proofbound/toolchains/translation.lock"

claim_manifests = ["claims/*.toml"]
translation_units = ["proofbound/translations/*.toml"]
model_check_units = ["proofbound/model-checks/*.toml"]
```

### 11.2 Claim manifest

```toml
schema = "proofbound-claim/1"
id = "DEMO-TRANSFER-001"
title = "Accepted transfers conserve value"
statement = "For every accepted transfer, debit + credit is conserved."
formal_declaration = "ProofboundDemo.Transfer.accept_conserves"
statement_sha256 = "…"
subject = "rust:allowance-kernel::decide_transfer"
profile = "source-refined"

evidence = [
  "translation:transfer-kernel",
  "theorem:transfer-refinement",
  "kani:transfer-bounds",
  "test:cross-language-vectors",
]

assumptions = ["DEMO-IDENTITY-AX-001"]
```

`statement_sha256` binds the claim to the elaborated, pretty-printed statement
recorded by the compiled axiom audit (§8.2). Drift between the manifest digest
and the compiled statement — a silently restated theorem — renders the claim
`INVALID`. Subject identity is a symbol-level binding plus the claim's source
closure; Proofbound does not pretend to bind object code, and says so in the
receipt.

### 11.3 Translation unit

```toml
schema = "proofbound-translation-unit/1"
id = "transfer-kernel"
adapter = "charon-aeneas"
packages = ["allowance-kernel"]
start_from = ["allowance_kernel::decide_transfer"]
opaque = []
include = []
generated_dir = "lean/Generated/Transfer"
handwritten_refinement = "lean/Allowance/TransferRefinement.lean"
determinism_runs = 2
determinism_normalization = "pretty-printed-llbc/1"
forbid_generated_axioms = true

[[external_bridges]]
# Hand-authored files that live inside the generated tree (external
# function/type models). Declared and byte-pinned, never discovered by
# convention.
file = "lean/Generated/Transfer/FunsExternal.lean"
reviewed_sha256 = "…"

[[template_axioms]]
# Quarantined translator placeholder axioms; never compiled into claims.
file = "lean/Generated/Transfer/Templates.lean"
count = 3
compiled = false

[[warning_inventory]]
# Known upstream translator warnings/sorries, pinned by artifact and line;
# a new one fails the build.
artifact = "lean/Generated/Transfer/Funs.lean"
line = 118
kind = "upstream-sorry"
```

The schema is deliberately wider than a package-and-symbols pair because the
reference implementation needed every one of these fields in practice:
start-from, opaque, and included symbol sets drive the extractor invocation;
hand-reviewed external bridges live inside the generated tree and must be
byte-pinned; translator template axioms exist and must stay uncompiled with
exact per-file counts; raw LLBC is nondeterministic and must be normalized
before byte comparison; and upstream translator warnings must be inventoried
so that new ones fail the build instead of scrolling past.

**Inversion requirement.** In Auths Proof, the qualification manifest is a
cross-check of hard-coded orchestration: extractor flags, symbol lists, output
mappings, and even unit cardinalities are literals in orchestration source,
and the manifest merely agrees with them — adding a translation unit means
editing orchestrator code. Proofbound MUST invert this relationship. The
manifest is the single source from which the adapter derives every tool
invocation; no adapter may embed per-project symbol lists, path mappings, or
unit counts. Adding a translation unit is a manifest change, not an
orchestrator change. This inversion is new engineering, not extraction of
existing machinery, and Section 15.2 grades it accordingly.

Lists of packages, symbols, generated destinations, external bridges, and
claim mappings MUST live in manifests rather than orchestration source code.

### 11.4 Closure reuse

Large source and tool closures are defined once and referenced by digest.
Claims do not repeat hundreds of identical paths. Closure records retain
individual file hashes and exact transitive membership.

Proofbound distinguishes:

- semantic closure;
- runner closure;
- presentation closure; and
- external evidence closure.

A claim binds only the closures relevant to its meaning, preventing unrelated
documentation or dashboard edits from invalidating long-running computation
while remaining fail-closed about semantic changes.

**Granularity.** The floor is file-level closure per claim root: the
transitive source-dependency closure of the module declaring the claim's
theorem, as reported by the build tool (for Lean, the source-dependency
closure of the declaring module; for Rust, the package closure reachable from
the translation roots via `cargo metadata`). Per-declaration closure is an
aspirational refinement and MAY be added later without schema change. What is
prohibited is the reference failure mode: a single project-global closure
copied identically into every claim, which conveys no per-claim dependency
information while inflating the manifest by orders of magnitude.

## 12. Command-line UX

The initial CLI is `proofbound`.

### 12.1 Commands

```text
proofbound init
proofbound doctor
proofbound check [--claim ID] [--profile PROFILE] [--fresh]
proofbound status [--json]
proofbound claim ID [--graph] [--json]
proofbound explain ID
proofbound reproduce UNIT
proofbound assumptions [--claim ID]
proofbound graph [--format dot|json|html]
proofbound diff BASE..HEAD
proofbound update UNIT
proofbound demo NAME
```

### 12.2 Behavior

- `init` scaffolds a Tier 0 project (§4.3): claim and assumption manifests
  with one worked placeholder claim bound to an existing test, and no new
  toolchain requirements. It does not invent domain claims.
- `doctor` verifies tools, versions, required capabilities, and reports which
  units the host can afford (§16.3).
- `check` materializes evidence and compiles the assurance graph. It writes
  receipts and the evidence store only; it never modifies committed files,
  including generated code. Valid cached receipts are reused (§16.2), and
  `--fresh` forces re-execution.
- `status` reports all claim classifications and publication blockers, and
  distinguishes "verified from cache" from "re-verified now."
- `claim` shows the complete evidence and assumption closure.
- `explain` answers why the claim has its current status and how to improve it.
- `reproduce` reruns one exact evidence unit.
- `assumptions` exposes project and external hypotheses prominently.
- `graph` exports the assurance graph.
- `diff` reports claim, theorem, axiom, TCB, and closure changes between
  revisions, and classifies **assurance regressions**: a new assumption or
  newly undischarged premise; an enlarged TCB; a linkage downgrade
  (`ARTIFACT_BOUND` → `TRANSCRIBED`, `REFINED` → `MODEL_ONLY`); an
  evaluation downgrade (`kernel` → `native`); a formal-facet downgrade; a
  narrower registered bounded domain (reported as `incomparable` where the
  two domain registrations cannot be ordered); removed mutation coverage; or
  a weakened source closure. Regression handling in CI is defined in §18.1.
- `update` is the only command allowed to rewrite committed generated
  artifacts — translated Lean, regenerated fixtures, refreshed closures. It
  requires a clean tree and produces a reviewable diff.
- `demo` runs a registered demonstration and displays its proof status.

The `check`/`update` boundary is a hard contract, not a convention: `check`
is safe to run anywhere, any time, with no possibility of mutating the
reviewed tree; `update` is the single, auditable door through which committed
generated state changes.

Every human-facing report — `status`, `claim`, `explain`, and any rendered
projection — MUST include a **"not proved / out of scope"** section
enumerating the claim's `OPEN` obligations, undischarged premises, explicit
assumptions, and registered exclusions. Omitting the section is not a
formatting choice; a report without it is invalid output.

No command silently edits proof manifests or accepts stale evidence.

### 12.3 Error contract

Errors include:

- stable code;
- claim or unit ID;
- file and logical path;
- byte offset where applicable;
- expected and actual identities;
- affected downstream claims; and
- remediation.

## 13. Initial repository structure

The project SHOULD begin with:

```text
proof-bound/
├── AGENTS.md
├── README.md
├── LICENSE
├── proofbound.toml
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── lean-toolchain
├── lakefile.toml
├── lake-manifest.json
├── pyproject.toml
├── uv.lock
├── justfile
│
├── crates/
│   ├── proofbound-core/          # IDs, schemas, graph, status, policies
│   ├── proofbound-manifest/      # strict TOML/JSON readers
│   ├── proofbound-evidence/      # receipts and content-addressed evidence
│   ├── proofbound-cli/           # operator interface
│   ├── proofbound-verify/        # independent receipt verifier (§10.4)
│   ├── proofbound-adapter-lean/
│   ├── proofbound-adapter-aeneas/
│   ├── proofbound-adapter-kani/
│   └── proofbound-adapter-test/
│
├── lean/
│   ├── Proofbound/
│   │   ├── Assurance.lean        # reusable declaration/axiom audit support
│   │   ├── Artifact.lean         # artifact/digest theorem combinators
│   │   └── Result.lean           # canonical evidence result types
│   └── lakefile.toml
│
├── python/
│   └── proofbound/
│       ├── __init__.py
│       └── adapter.py            # optional Python adapter protocol/client
│
├── schemas/
│   ├── project.schema.json
│   ├── claim.schema.json
│   ├── evidence.schema.json
│   ├── assumption.schema.json
│   ├── translation-unit.schema.json
│   ├── adapter-protocol.schema.json
│   └── receipt.schema.json
│
├── templates/
│   ├── artifact-checker/
│   ├── rust-aeneas-refinement/
│   └── explicit-assumption/
│
├── claims/                       # Proofbound's own self-assurance claims
├── assumptions/                  # Proofbound's own explicit assumptions
├── proofbound/
│   ├── translations/
│   ├── model-checks/
│   ├── policies/
│   └── toolchains/
│
├── demo/
│   ├── allowance/                # first complete vertical
│   ├── artifact-certificate/     # canonical-byte pattern
│   └── README.md
│
├── docs/
│   ├── specs/
│   │   └── 0001_initial_spec.md
│   ├── adr/
│   ├── guides/
│   └── assurance/
│
└── .github/workflows/
    └── ci.yml
```

This is the target shape, not the M0 deliverable: per the milestone order in
Section 20, the `crates/proofbound-*` core is extracted after the demo
verticals exist, not scaffolded first. The Rust CLI is the orchestration
authority. Python support is an adapter, not a second manifest or policy
implementation. Lean support code remains small; domain theorems remain
project-owned.

## 14. Initial demonstration: allowance transfer

The first demo MUST be small enough to understand in one sitting and rich
enough to demonstrate explicit proof boundaries.

### 14.1 Scenario

A Python CLI submits a canonical transfer request. A pure Rust kernel accepts or
denies the transfer under balances, a per-transfer cap, and an authorization
signal. If accepted, it returns new balances and a stable decision code.

### 14.2 Claims

The demo registers:

1. Accepted transfers conserve total value.
2. Accepted transfers never overdraw the source balance.
3. Accepted transfers never exceed the configured cap.
4. Denied transfers do not return a mutated state.
5. The shipping Rust decision kernel refines the Lean decision relation.
6. Canonical request bytes decode to the same bounded request in Rust and Lean.
7. The Python orchestrator submits the exact canonical bytes recorded in the
   receipt. This is a runtime property of the orchestrator: it is registered
   as `example-test` evidence plus a receipt digest comparison, renders as
   `TESTED`, and is never displayed as proved. The demo classifying its own
   weakest claim honestly is part of the demonstration.

### 14.3 Explicit assumption

The demo deliberately includes one understandable hypothesis:

```text
DEMO-IDENTITY-AX-001:
The external identity provider's `authorized = true` response correctly
identifies the holder of the source account.
```

Lean does not prove the external provider honest. The public theorem states
what follows under this assumption. The UI displays the dependency rather than
hiding it in prose.

### 14.4 Evidence

- Charon/Aeneas translates the pure Rust decision kernel.
- Lean proves the conservation, no-overdraft, cap, denial, and refinement laws.
- Kani checks fixed-width arithmetic and registered bounded state cases.
- Rust and Lean independently decode canonical request fixtures.
- Python/Rust/Lean conformance vectors exercise the byte boundary.
- Registered mutation witnesses (Section 5) show that removing each guard
  breaks a registered check.

### 14.5 Demo UX

```text
+------------------------------------------------------------------+
| Proofbound · Allowance Transfer                                  |
+------------------------------------------------------------------+
| From balance [100]  To balance [25]  Amount [30]  Cap [40]       |
| Identity provider: AUTHORIZED                  [Evaluate]         |
+------------------------------------------------------------------+
| Decision: ACCEPTED                                               |
| New balances: 70 / 55                                            |
+------------------------------------------------------------------+
| Claims                                                           |
| ✓ Conservation                 PROVED · REFINED                  |
| ✓ No overdraft                 PROVED · REFINED                  |
| ✓ Cap respected                PROVED · REFINED · BOUNDED        |
| ✓ Canonical bytes submitted    TESTED · receipt digest           |
| ! Identity is correct          EXPLICIT ASSUMPTION               |
| ? Provider executed transfer   OUT OF SCOPE                      |
+------------------------------------------------------------------+
| [View assurance graph] [View exact receipt] [Mutate implementation]|
+------------------------------------------------------------------+
```

All three kernel laws are proved over the same refined kernel, so all three
carry `REFINED` linkage; the cap law additionally carries bounded arithmetic
evidence from Kani. The mutation control is part of the teaching experience:
selected safe source mutations should visibly turn a green claim invalid and
show which evidence caught the defect.

## 15. Reusable tooling extracted from the reference projects

Section 1 calls the reference patterns "working." That word must be earned:
some reference machinery is mature and extractable, and some is aspirational,
partial, or compromised in its own repository. A framework whose thesis is
that evidence must never be presented as stronger than it is applies the same
rule to its own provenance. Each item below is therefore graded:

- **extract** — the mechanism works in the reference and generalizes;
- **redesign** — the idea is right but the reference implementation is
  compromised, partial, or does not generalize; Proofbound rebuilds it.

These assessments are themselves claims about repositories at a point in
time, so they are pinned: Auths Proof audited at commit `95c9d45` (branch
`codex/formal-source-closure`); Matrix Math audited at commit `fb7afc7`.
The Matrix Math repository has no remote, so its digest is a local-only
identity — the assessment is reproducible only against that local clone,
and this caveat is part of the record, not a footnote to be dropped.

### 15.1 From Matrix Math

| Mechanism | Grade | Notes |
|---|---|---|
| Canonical bounded certificate envelopes | extract | |
| Independent artifact decoders | extract | Fully independent on the ω track only. The rank track binds bytes via an untrusted round-trip re-encoder; Proofbound classifies that shape as `TRANSCRIBED` (§7.1.1) rather than inheriting the ambiguity. |
| Artifact/claim digest theorem combinators | redesign | Only a minority of committed generated modules use digest-conjoined theorems. Proofbound makes digest binding the default (§7.1), not the exception. |
| Generated result-local Lean modules | extract | |
| Compiled axiom audits | redesign | The compiled audit covers the claim inventory, but generated per-certificate modules are gated by text-parsing `#print axioms` output — two mechanisms with different strength. Proofbound unifies on the compiled audit for both (§8.2). |
| Certification profiles | extract | Including the kernel-vs-native distinction, surfaced at evidence level (§5). |
| TCB and source-closure receipts | extract | |
| Deterministic source digests | extract | |
| Independent checker conformance | extract | |
| Fail-closed release verification | redesign | The reference implementation parses its release manifest by substring search — precisely what Section 18 prohibits — and its CI assurance gate went stale against the active manifest. Rebuild on structured parsing, with the gate itself registered under self-application (§19) so staleness is a visible `INVALID`, not silence. |

Do not generalize Matrix Math's equations, certificate semantics, optimization
campaign machinery, or checker implementation.

### 15.2 From Auths Proof

| Mechanism | Grade | Notes |
|---|---|---|
| Manifest-driven translation units | redesign | The reference manifest is a cross-check of hard-coded orchestration constants — extractor flags, symbol lists, output mappings, literal unit counts. Proofbound inverts the relationship so manifests drive invocation (§11.3). |
| Charon/Aeneas deterministic regeneration | extract | Run-twice byte comparison over normalized (pretty-printed) LLBC, plus extraction-environment hardening against ambient compiler flags. |
| Quarantined generated Lean | extract | With one correction: hand-authored external bridges living inside the generated tree must be declared and byte-pinned in the manifest (§11.3), not discovered by convention. |
| Representation-premise registration | extract | Elevated to a normative status rule (§6.3.2). |
| Handwritten refinement theorem registration | extract | |
| Kani harness inventory and ungated-harness rejection | redesign | The reference gate is a package-level textual scan for `#[kani::proof]`; a `cfg_attr`-wrapped or reformatted attribute escapes it, and no per-harness registry exists. Proofbound requires a per-harness inventory derived from tool metadata (e.g. `cargo kani list`), matched bidirectionally against the manifest. |
| Claim-to-evidence compliance inventory | redesign | The reference theorem inventory is a hand-maintained literal list covering a fraction of declared theorems; nothing forces a new theorem to be registered. Proofbound diffs the compiled environment's declaration set against the registered inventory so an unregistered claim-scope declaration fails closed (§17). |
| Translation source closures | extract | Including build-metadata-driven package-closure discovery so a newly added module cannot escape the closure. |
| Generated-code drift checks | redesign | The reference byte-verifies generated code only on push events; pull-request CI regenerates and accepts drift. The comparison mechanism extracts; the policy is rebuilt fail-closed for every event class (§18.1). |
| Layered project architecture enforcement | extract | |

Do not generalize Auths Proof's authorization semantics, provider profiles,
lifecycle rules, or domain receipt meaning.

### 15.3 Clean abstraction boundary

Proofbound owns **mechanism**, not application meaning:

```text
Reusable mechanism                   Project-owned meaning
------------------                   ---------------------
claim graph                           theorem statements
artifact envelope                     certificate semantics
translation orchestration             Rust kernel behavior
axiom inventory                        accepted hypotheses
source closure                         semantic source selection
assurance policies                     publication claim language
evidence receipts                      domain interpretation
```

New adapters begin vertically. Shared behavior is extracted only after two
complete consumers demonstrate an identical contract. Similar command shapes
are not sufficient evidence for a shared semantic abstraction. This rule
binds the framework core itself: the milestone order in Section 20 builds
complete verticals before extracting shared mechanism from them.

## 16. Provenance, reproducibility, and cost

### 16.1 Evidence binding

Every evidence record MUST bind:

- project revision;
- clean/dirty tree state;
- semantic source closure;
- exact input artifact digests;
- generated artifact digests;
- complete tool identity;
- command and environment allowlist;
- start and completion timestamps as diagnostic metadata;
- deterministic result identity;
- resource bounds; and
- adapter version.

Translation and generation operations run twice and must produce byte-identical
outputs unless the adapter declares and normalizes an audited nondeterministic
field (as with raw LLBC, normalized to a pretty-printed projection). Network
retrieval is forbidden during verification unless represented as a separately
sealed external-evidence step.

Receipts are canonical and content-addressed. Human reports are projections of
receipts and never sources of truth.

### 16.2 Evidence caching

Fail-closed re-verification of everything on every invocation will not be run
by humans, and a verification tool nobody runs verifies nothing. `check`
therefore reuses evidence:

- A receipt is reusable when its cache key is unchanged: semantic closure
  digest, input artifact digests, toolchain identity, adapter version, and
  unit configuration digest.
- Reuse is recorded in the receipt chain; `status` distinguishes "verified
  from cache" from "re-verified now."
- `--fresh` forces re-execution of any unit.
- An unverifiable or corrupt cached receipt causes re-execution, never
  acceptance.

Caching changes cost, never meaning: a cached receipt asserts exactly what the
original run asserted, against exactly the same closure. The closure-reuse
model of Section 11.4 exists precisely so this cache key is fine-grained
enough to be useful.

### 16.3 Cost realism

The reference costs are real and shape the design: the Auths Proof formal CI
phase builds pinned Charon/Aeneas via Nix, needs on the order of 25 GiB of
disk and a ~28-minute budget, with Kani contributing minutes more; Matrix
Math's ω track leans on native evaluation for exactly this reason. Proofbound
therefore requires:

- every translation, model-check, and proof unit declares an expected
  resource budget (time, disk, memory) in its manifest;
- `doctor` reports which units the host can afford;
- adapters report actual cost in receipts so budgets stay honest; and
- budget overruns are diagnostics, never silent truncation of coverage.

## 17. Security and failure policy

Proofbound treats manifests, generated files, external tool output, and evidence
as untrusted inputs.

It MUST:

- reject unknown schemas and fields;
- reject path traversal and symlinks at sealed boundaries;
- meter input bytes and collection counts;
- reject duplicate IDs and ambiguous paths;
- reject missing, stale, or extra generated files;
- reject unregistered Lean declarations, Kani harnesses, and translation
  units — for Lean, by diffing the compiled environment's declaration set
  against the registered inventory rather than by source-text scanning; for
  Kani, by per-harness tool-metadata inventory rather than attribute grep;
- reject successful subprocess exit without expected evidence;
- never execute arbitrary manifest shell strings;
- use typed adapter command construction;
- record but never expose secrets;
- publish no stronger status when an adapter is unavailable; and
- preserve the last valid receipt when a refresh fails.

## 18. CI and release

The initial CI stages are:

1. manifest/schema validation;
2. source-closure validation;
3. Rust format, build, lint, and test;
4. Python lock and focused tests;
5. Lean build and compiled axiom audit;
6. Charon/Aeneas deterministic translation;
7. Kani harness inventory and bounded checks;
8. cross-language fixture conformance;
9. assurance-graph compilation;
10. demo end-to-end verification;
11. release receipt reproduction; and
12. independent receipt verification: `proofbound-verify` (§10.4) recomputes
    the graph and facets from the receipts the earlier stages produced, and
    its verdict — not the orchestrator's — is the verdict CI reports.

### 18.1 Verify vs update policy

Every CI event class — pull request, push, schedule, release — runs
verify-only gates: `check`, closure validation, and drift comparison. No CI
event may regenerate artifacts and accept the result. Specifically prohibited
is the reference asymmetry in which pull-request CI runs the update path and
packages the resulting drift for later review while only push CI
byte-verifies: under that policy, "generated code is verified on every
change" is false exactly when changes are being proposed.

Regeneration runs only through `proofbound update`, locally or in a dedicated
update workflow whose sole output is a reviewable diff — which then passes
the same verify-only gates as any other change. Releases are produced from a
clean tree by verify-only steps.

**Assurance regressions require approval, not silence.** CI runs
`proofbound diff` against the merge base and rejects any change carrying an
assurance regression (§12.2) unless the change includes an approval record:
a first-class `review` node bound to the digest of the exact base and head
revisions and enumerating the specific regressions it approves. The approval
is itself graph evidence — reviewable, attributable, and invalidated if the
diff it approved changes. A regression without an approval record fails; an
approval record without a matching regression is rejected as stale.

### 18.2 Release contents and verification

A release contains:

- binaries and package checksums;
- canonical schemas;
- assurance graph;
- per-claim receipts;
- assumptions ledger;
- TCB ledger;
- source and toolchain closures;
- demo receipts; and
- signed build provenance where available.

Release verification runs through `proofbound-verify` (§10.4), so a release
is checkable by a third party holding only the release artifacts and the
verifier binary. It MUST parse structured manifests normally; string-search
field extraction is prohibited. Durable retrieval and every recorded digest,
claim, theorem, assumption, and TCB component must be revalidated.

## 19. Self-application

Proofbound MUST eventually use Proofbound to describe its own claims. Initial
self-claims include:

- manifests reject unknown fields;
- claim status cannot be manually upgraded;
- undeclared project axioms invalidate a theorem claim;
- ungated harnesses invalidate bounded coverage;
- stale generated translation invalidates source refinement;
- receipt identity changes when semantic source changes;
- presentation-only changes do not alter semantic closure;
- the orchestrator and `proofbound-verify` derive identical facets over the
  registered synthetic-graph corpus (§10.4), so a derivation bug in either
  implementation surfaces as cross-check divergence rather than as silently
  optimistic status; and
- the CI gates named in Section 18 are themselves registered subjects, so a
  stale or disconnected gate surfaces as `INVALID` rather than as silence.

Self-application does not imply that the entire orchestrator is formally
verified. Its own graph must expose which parts are proved, tested, reviewed,
or open.

## 20. Implementation milestones

The milestone order follows the extraction rule of Section 15.3: shared
mechanism is extracted only after complete consumers exist. The framework
core is not exempt from its own rule, so the vertical demos come first and
the generic core is extracted from them.

The same discipline applies to the adoption ladder (§4.3): no infrastructure
is built for a tier that has no real consumer yet, and the claim/assumption
UX is validated at Tier 0 — by real use — before the heavy adapter stack
exists. Two independent reviews of this specification converged on the same
risk, over-building framework before validating the daily-development
experience; this ordering is the protection.

### M0: repository foundation

- Root manifests, pinned toolchains, workspace layout, CI skeleton, and
  contribution instructions.
- No generic core yet. Demo-local manifests MAY be ad hoc at this stage;
  every ad-hoc structure is logged as an extraction candidate.
- Acceptance: clean bootstrap on a fresh machine.

### M1: allowance demo, built vertically

- The demo begins as its own Tier 0 consumer: its claims and assumptions are
  registered first, bound to ordinary tests, and the ledger drives the
  demo's development per the workflow of Section 4.1 — dogfooding the
  claim/assumption UX before any formal machinery exists.
- Then the vertical: Python orchestrator, pure Rust kernel, Lean model,
  explicit identity assumption, canonical fixtures, terminal UI, and thin
  demo-local orchestration (hard-coding permitted and recorded), promoting
  the registered claims up the tiers.
- Acceptance: the demo displays the exact proof boundary and mutation
  witnesses fail as registered — and its own commit history shows the Tier 0
  ledger existed before the proofs.

### M2: artifact-certificate demo, built vertically

- Second complete consumer, using the artifact-soundness pattern with
  digest-default binding (§7.1).
- Acceptance: byte-level acceptance-implies-meaning and digest theorems
  reproduced from clean state; one axiom-free and one explicitly
  axiomatized artifact claim.

### M3: core extraction

- Extract canonical schemas, graph construction, faceted status derivation,
  policies, receipts, and the CLI (`doctor`, `status`, `claim`, `explain`)
  from the two demos plus the reference-repository study; migrate both demos
  onto the extracted core.
- Build `proofbound-verify` (§10.4) against the same specification with no
  shared source, plus the registered synthetic-graph corpus that
  cross-checks the two derivations.
- Acceptance: both demos run through the shared core with no demo-specific
  logic in core source; synthetic graph tests prove no status can be
  upgraded by omitting evidence or assumptions — in both implementations;
  `init` produces a working Tier 0 ledger on an arbitrary existing
  repository, not only on the demos; every extracted abstraction carries a
  case record naming its two consumers.

### M4: adapter hardening

- Manifest-driven Charon/Aeneas invocation (the Section 11.3 inversion),
  compiled declaration/axiom audit applied to all generated modules,
  per-harness Kani inventory, unregistered-declaration rejection,
  deterministic regeneration, and source closures.
- Acceptance: the allowance kernel is translated and refined purely from
  manifests; an ungated harness, unregistered theorem, or generated axiom
  fails closed.

### M5: reference adoption pilot

- Adopt Proofbound for a bounded subset of claims in at least one reference
  project (Matrix Math or Auths Proof). This is the cheapest honest test of
  generality — cheaper and more informative than a synthetic third demo,
  because the reference repos contain the real-world irregularities the
  demos were built to avoid.
- Acceptance: the pilot subset's claims compile in the reference repository
  without forking the core; every divergence the pilot forces is recorded as
  an abstraction case record or a spec change, not patched around.

### M6: publication and packaging

- Signed releases, reusable templates, documentation, and an HTML graph
  viewer.
- Acceptance: a fresh external repository can adopt Proofbound using only
  documented manifests and adapters.

No milestone is complete because a test suite merely runs. Its stated
acceptance evidence must appear in the compiled assurance graph.

## 21. Success criteria

Proofbound succeeds when:

1. A developer can identify every important claim and residual assumption from
   one command.
2. A team with an ordinary existing repository reaches a useful Tier 0 claim
   ledger — claims registered, assumptions named, tests bound — in under a
   day, without installing a proof assistant or model checker.
3. A reviewer can trace public language to exact bytes or shipping source.
4. Changing a theorem, source subject, assumption, toolchain, or generated file
   invalidates the relevant evidence automatically.
5. Tests, bounded checks, refinements, and theorems are never conflated —
   including the sub-distinctions: kernel-checked vs native-evaluated proofs,
   and byte-bound vs transcribed artifact claims.
6. A second unrelated demo integrates without editing orchestration source.
7. Domain-specific semantics remain independent and reviewable.
8. Known gaps become smaller, named engineering objects rather than prose debt.
9. At least one reference project adopts Proofbound for a subset of its live
   claims, with every forced divergence recorded rather than patched around.
10. The framework makes partial formal assurance useful without pretending it
    is complete formal verification.

## 22. Governing principle

Proofbound exists to make the boundary of knowledge executable.

The framework does not ask teams to choose between ordinary software testing
and perfect verification. It gives them a disciplined path between those
extremes: state the claim, prove what can be proved, link the proof to what
ships, test what remains empirical, name every assumption, and refuse to hide
the gaps.
