# Specification 0001: Proofbound and Proof-Driven Development

**Status:** Initial implementation specification

**Version:** 0.10.0

**Date:** 2026-08-31

**Project:** Proofbound

**Process:** Proof-Driven Development (PDD)

### Revision history

- **0.10.0** — exact executable inventories: fixes the five adapter operation
  response meanings; requires passed observed-process evidence to carry a
  nonempty exact inventory and only successful, untruncated runs; closes the
  canonical-artifact and independent-check result ABIs; verifies generators by
  fresh `--update` reproduction; rejects duplicate raw Kani metadata keys; and
  advances translation units to `/3` with an exact typed supported-local
  closure (§7.1, §10.2, §11.2–11.3, §11.5; ADR 0016).
- **0.9.0** — executable trusted transcription: introduces the closed
  `proofbound-evidence-unit/2` transcription route and fixed Python driver ABI,
  derives distinct transcriber and re-encoder TCB roles from observed driver
  bytes, carries all four compared artifact identities without a checker-
  authored success Boolean, and adds the immutable Tier 1 `transcribed`
  profile (§7.1.1, §9.1.1, §11.2.1; ADR 0015).
- **0.8.0** — authoritative translation manifests: replaces the flat,
  partially advisory translation-unit format with ordered typed
  Charon/Aeneas invocations, exact intermediate and output identities, a
  closed produced-to-destination map, executable external-source-root
  resolution, and explicit generated-tree ownership (§11.3; ADR 0014).
- **0.7.0** — artifact-binding security boundary: derives
  `ARTIFACT_BOUND` only from the exact elaborated root proposition carried by
  an admitted theorem, removes checker-authored linkage booleans, makes the
  complete canonical theorem statement available to the independent verifier,
  and replaces the explicit `2-binding-preview` identities with the final
  version-2 evidence and release envelopes (§5, §7.1, §9.4, §10.2, §10.4;
  ADR 0012). The same versioned transition completes the deferred
  receipt-fidelity work: exact registered bounded assumptions, nullable
  unknown peak memory, separate internal/reader/rendered claim text, and
  complete ordered execution provenance with an explicit distinction between
  observed processes and compiler-internal derivations (§6.3.2, §9.7, §11.5,
  §16;
  ADR 0013).
- **0.6.0** — bounded-evidence fidelity: requires the bounded receipt's solver
  and per-harness unwind bounds to equal the registered model-check unit, with
  exact harness/unwind key coverage and nonzero bounds (§9.7); and requires
  bounded reader output to preserve the compiled claim property while
  appending the explicit registered finite domain (§6.3.2).
- **0.5.0** — bootstrap-contract reconciliation: defines the Tier 0 `ledger`
  profile as an immutable built-in (§9.1); makes every shipped project and
  claim manifest field normative (§11.1–11.2); closes the adapter observation
  and canonical evidence wire schemas (§10.2); and records that the initial
  implementation bootstrap cannot supply the historical ledger-before-proofs
  evidence required of later dogfood milestones (§20 and ADR 0001).
- **0.4.0** — precision revisions: separates trusted-transcription evidence
  from artifact soundness (§5, §7.1.1); defines a versioned canonical Lean
  expression encoding for statement identity (§8.2, §11.2); inventories only
  explicitly attributed public Lean claims (§8.2, §17); separates handwritten
  external bridges from generator-owned directories (§11.3); and pins the
  reference audits to full revisions and source-closure identities (§15).
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
- **0.1.0** — initial draft.

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
| **1** | Trusted transcription, bounded model checking, independent and exhaustive checks | A registered transcription driver and/or Kani (or equivalent) | `OPEN` + `TRANSCRIBED`, or `BOUNDED_CHECKED` |
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
| `artifact-soundness` | A checked artifact identity matches the literal identity derived independently from an admitted theorem's exact elaborated binding proposition. |
| `trusted-transcription` | Typed values are transcribed outside the theorem boundary and byte identity is enforced by an external round-trip; the transcriber and re-encoder are trusted components. |
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
  enlarges the trusted computing base (§9.6) and must be visible at the
  evidence level, not only in the trust profile.
- **Binding mode.** Every `artifact-soundness` record MUST state binding mode
  `bytes-in-theorem` or `digest-theorem`. Every `trusted-transcription` record
  MUST state binding mode `external-round-trip` (Section 7.1.1). These evidence
  kinds and binding modes are not interchangeable, and the graph never
  conflates them.
- **Binding derivation.** A checker outcome, theorem name, or Boolean assertion
  is never a binding. Version 0.7 admits `digest-theorem` only when the exact
  outermost elaborated statement is
  `Proofbound.Artifact.DigestBindingV1 claimId artifactSchema logicalName
  expectedSha256 bytes meaning`, the first four arguments are direct canonical
  string literals, and the proposition establishes both the SHA-256 identity
  and `meaning bytes`. The complete `lean-expr-cbor/1` statement is carried in
  theorem evidence so both status engines recompute its identity and parse it
  independently. `bytes-in-theorem` remains reserved but fails closed until an
  equally exact typed proposition and portable byte comparison are specified.

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

The legal endpoint kinds are closed and normative:

| Edge kind | Legal `(from, to)` node-kind pairs |
|---|---|
| `proves` | `(theorem, claim)` |
| `refines` | `(translation-unit, claim)` |
| `decodes` | `(artifact, claim)` |
| `checks` | `(test-suite, claim)`, `(model-check-unit, claim)` |
| `generated-from` | `(artifact, subject)` |
| `depends-on` | `(claim, subject)`, `(subject, artifact)`, `(theorem, theorem)` |
| `assumes` | `(claim, assumption)`, `(claim, premise)`, `(theorem, premise)`, `(assumption, claim)`, `(claim, claim)` |
| `discharged-by` | `(premise, theorem)` |
| `cross-checks` | `(test-suite, claim)`, `(model-check-unit, claim)` |
| `covers-bounded-domain` | `(model-check-unit, claim)` |
| `binds-digest` | `(artifact, claim)` |
| `reviewed-by` | `(review, claim)`, `(assumption, review)` |
| `admitted-by-policy` | `(claim, policy)` |

`source-closure`, `toolchain`, and `tcb-component` nodes have no legal edge in
this schema version. They remain typed inventory nodes and MUST NOT acquire an
invented relationship merely to make them connected.

The trusted in-process construction API MUST encode this table in its types:
callers select an edge relation whose marker type accepts only the legal typed
endpoint references. A generic unchecked `GraphEdge { from, to, kind }`
constructor MUST NOT be public. A compiler assembling nodes dynamically MAY use
a checked constructor derived from the same single table and MUST handle its
error before emitting the graph. Because canonical JSON is an untrusted input,
deserialization necessarily remains capable of representing an illegal edge;
both the core validator and the dependency-independent release verifier MUST
recheck the complete table and fail closed. Compile-fail tests MUST demonstrate
that at least one kind-correct but relation-invalid construction, such as
`test-suite --proves--> toolchain`, is rejected by Rust's type checker.

Node identities retain one wire-level `NodeId` representation so graph records
remain compact and language-neutral. Trusted constructors wrap those identities
in node-kind marker references before an edge can be built; this closes
claim/theorem/subject confusion at the construction boundary without requiring
fourteen distinct serialized ID formats. Unknown node or edge kinds and illegal
endpoint pairs MUST be rejected. Cycles are allowed only for declared mutual
theorem dependencies internal to one proof environment; cycles in artifact
generation or provenance are invalid.

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
| `artifact-soundness` whose admitted theorem has the exact typed `DigestBindingV1` root and matching checked artifact identity (§5, §9.4) | `ARTIFACT_BOUND` |
| `trusted-transcription` with binding `external-round-trip` (§7.1.1) | `TRANSCRIBED` |
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
- A Tier 0 ledger MAY register a future theorem premise before its owning
  theorem evidence exists. Such a premise is attached directly to the claim by
  an `assumes` edge, has no `theorem_evidence` identity, is necessarily
  undischarged, and cannot contribute proof or linkage strength. Once the
  theorem is registered, the premise record MUST bind that exact theorem
  evidence identity. This narrow bootstrap form keeps a known representation
  obligation visible without fabricating a theorem receipt.
- **Precedence.** The formal facet takes the strongest evidence the policy
  admits. Weaker evidence is retained and displayed beneath the summary; it
  is never discarded or double-counted.
- **`INVALID` semantics.** `INVALID` is both a reportable status and a build
  failure: it renders in `status` output so the operator can see which claim
  broke and why, and the presence of any `INVALID` claim causes a nonzero
  exit. `INVALID` overrides all other facets.
- **Bounded language.** A `BOUNDED_CHECKED` claim's `public_statement` is the
  derived status text, never a replacement for the claim's internal
  `statement`. Its base text is the claim's optional `public_language` when
  present and otherwise its internal `statement`, followed by the literal
  separator ` Registered finite domain: ` and the registered finite-domain
  language.
  The property is never replaced by domain-only wording, and no unbounded
  language is emitted for bounded evidence. The version-2 compiled claim keeps
  `statement` and optional `public_language` as separate fields, while the
  reported status keeps the derived `public_statement`; both status engines
  independently reproduce this composition. The same composition applies
  when an explicitly policy-admitted exhaustive finite check yields `PROVED`.
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
             typed digest-and-meaning public theorem
                                  |
                                  v
                         artifact-bound claim
```

Requirements:

- canonical, bounded, versioned bytes;
- rejection of trailing, oversized, ambiguous, or non-canonical inputs;
- an independently implemented Lean decoder inside the theorem boundary;
- one attributed public theorem whose exact elaborated root is the versioned
  Proofbound digest-binding proposition and whose proposition connects the
  same bytes to both their domain meaning and literal SHA-256 identity;
- an independent diagnostic checker where feasible; and
- explicit separation between search/production and trusted checking.

Full byte binding has real cost: embedding published bytes in the theorem
generally requires native evaluation (which enlarges the TCB, §9.6) and grows
generated modules. That cost is recorded in the TCB ledger and the evidence
evaluation mode; it is not a reason to silently weaken the binding.

Checker stdout is a strict, route-specific ABI. A canonical-artifact checker
emits exactly one canonical JSON value with this closed shape (the displayed
digest is abbreviated only for readability):

```json
{"accepted":true,"artifact_logical_name":"artifact.pbac","artifact_sha256":"sha256:<64-lowercase-hex>","inventory":["artifact.pbac"],"schema":"proofbound-artifact-check-result/1"}
```

An independent checker emits the smaller closed shape:

```json
{"accepted":true,"inventory":["registered-item"],"schema":"proofbound-independent-check-result/1"}
```

Both require `accepted = true` and a nonempty, duplicate-free exact inventory.
Inventory strings are trim-nonempty, at most 4096 Unicode characters, and
contain no Unicode control character. The value uses canonical key ordering
and compact encoding with no trailing whitespace or second JSON value. Unknown,
defaulted, claim-linkage, theorem, and binding-validity fields are forbidden.
A nonzero exit, truncated output, false result, malformed or noncanonical JSON,
or inventory mismatch fails before evidence admission; checker failure text is
not part of this success ABI. `schemas/checker-result.schema.json` defines the
two records, while exact framing and registered-set equality are enforced by
the adapter.

The artifact report's logical name and digest are independently recomputed from
the registered checked input. A checker cannot author the claim ID, theorem
link, binding mode, or binding-validity booleans. The compiler joins that
identity to the typed theorem statement; the independent verifier repeats the
join from the portable expression wire.

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

- its evidence kind is `trusted-transcription` with binding mode
  `external-round-trip`;
- it is not `artifact-soundness` evidence, because no theorem establishes the
  binding between the published bytes and the theorem input;
- its linkage facet is `TRANSCRIBED`, never `ARTIFACT_BOUND` (§6.3.2);
- the transcriber and re-encoder join the claim's TCB inventory as
  `tcb-component` nodes; and
- profile `artifact-bound` (§9.4) rejects it.

Version 0.9 makes this route executable rather than taxonomic only. Its typed
manifest, connected two-step ABI, artifact comparisons, and derived TCB
identities are specified in Section 11.2.1. Neither an adapter exit status nor
a manifest-authored Boolean can substitute for those comparisons.

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

Public claim discovery is explicit rather than exhaustive over helper
declarations. A project marks each public claim theorem with a Proofbound
attribute carrying its stable claim ID:

```lean
@[proofbound_claim "DEMO-TRANSFER-001"]
theorem accept_conserves : TransferProperty := by
  -- proof
```

The Lean adapter MUST enumerate these attributes from the compiled environment,
not by scanning source text. Attributed declarations and claim manifests match
bidirectionally: duplicate IDs, an attributed declaration without a manifest,
or a manifest naming an unattributed declaration fail closed. Helper lemmas do
not carry the attribute and are not individually inventoried; their contribution
remains visible through the public theorem's transitive dependencies and axiom
audit. The attribute supplies identity only and cannot assert an assurance
status.

Attribution must not become the escape hatch: a theorem nobody attributes
would otherwise silently escape the inventory — the same failure shape as a
hand-maintained list. Two controls close the loop. A module registered as a
public-claim surface requires every theorem it declares to be attributed or
explicitly exempted with a recorded reason, and report generation refuses to
cite any unattributed declaration in public claim language. An unattributed
theorem can exist; it cannot be published.

The statement digest MUST be computed from a versioned canonical encoding of
the elaborated Lean expression, never from pretty-printer output. Version
`lean-expr-cbor/1` is canonical CBOR conforming to
`schemas/lean-expr-v1.cddl`: bound variables use de Bruijn indices; binder names,
source positions, and presentation metadata are excluded; constants use fully
qualified names; universe levels, binder information, projections, and literal
values are encoded explicitly; maps and integer forms use canonical CBOR; and
expressions containing unresolved metavariables or free variables are rejected.
The encoding version is part of the claim record and domain-separates the bytes
being hashed. Changing the encoding version is an explicit assurance migration,
not silent statement drift. The receipt additionally binds the Lean adapter and
toolchain identities used to elaborate and encode the expression.

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

### 9.1 `ledger`

- This is the built-in Tier 0 adoption profile.
- It admits registered property-test, example-test, mutation-witness, review,
  assumption, and open evidence; independent-check, exhaustive-check,
  theorem, artifact-soundness,
  source-refinement, and bounded-check evidence are not required or admitted
  as formal proof by this profile.
- Its strongest formal status is `TESTED`; absent passing empirical evidence is
  `OPEN`. It never emits `PROVED` or `BOUNDED_CHECKED`.
- Subject linkage is always `MODEL_ONLY`; stronger linkage evidence may remain
  visible only as non-admitted supporting evidence and cannot promote a
  Tier 0 claim.
- Every report includes the mandatory “not proved / out of scope” section,
  even when all registered Tier 0 tests pass.
- Explicit assumptions remain first-class and are never hidden by a passing
  test.

### 9.1.1 `transcribed`

- This is the built-in Tier 1 profile for the degraded binding in Section
  7.1.1.
- It requires passing `trusted-transcription` evidence whose binding is
  `external-round-trip`, whose typed artifact identities form the exact
  connected round trip in Section 11.2.1, and whose linkage derives as
  `TRANSCRIBED`.
- It requires no theorem and never turns transcription evidence into
  `PROVED`. In the absence of separately admitted formal evidence, the formal
  facet remains `OPEN` while the linkage facet is `TRANSCRIBED`.
- It does not admit `ARTIFACT_BOUND` or `REFINED`, and it makes no claim about
  a shipping implementation. A project needing those statements must select
  the corresponding stronger profile and supply its distinct evidence.
- The transcriber and re-encoder are separate TCB roles even when one pinned
  driver file implements both operations.

### 9.2 `kernel`

- Named theorem compiles.
- No project axioms.
- No `sorryAx`.
- Only configured foundational proof-system axioms are allowed.
- Evaluation mode is `kernel`.

### 9.3 `kernel-with-assumptions`

- Named theorem compiles.
- Every project axiom is explicitly registered and allowlisted.
- Claim output enumerates those assumptions prominently.

### 9.4 `artifact-bound`

- Satisfies `kernel` or `kernel-with-assumptions`; a composition with
  `native-evaluated` must record its exact native premise and TCB.
- The admitted theorem receipt carries the complete canonical elaborated
  statement and its recomputed statement identity.
- For `digest-theorem`, that statement is exactly the outermost
  `Proofbound.Artifact.DigestBindingV1` application defined in Section 5; the
  literal claim ID, schema, logical name, and SHA-256 identity are derived from
  theorem content rather than checker output.
- The derived artifact logical name and digest equal exactly one checked input
  artifact in the separate artifact-soundness record. Version-2 provenance
  carries that artifact's complete logical-name, digest, and byte-size identity;
  both status engines require an exact match, including `size_bytes`.
- `bytes-in-theorem` is not admitted in 0.7; `trusted-transcription` evidence
  remains `TRANSCRIBED`, never `ARTIFACT_BOUND` (§7.1.1).
- Canonical parsing, re-encoding, and trailing-byte rejection are required work
  of the registered checker, but checker-authored booleans have no
  status-bearing representation.

### 9.5 `source-refined`

- Translation is deterministic and pinned.
- Generated code compiles without undeclared axioms.
- A named theorem connects the translated production function to the semantic
  model under registered representation premises.

### 9.6 `native-evaluated`

- A certificate-specific native evaluation premise is registered.
- The policy states whether exactly one such premise is required.
- The native implementation and complete TCB inventory are bound.
- Every admitted theorem's evidence record carries evaluation mode `native`.

### 9.7 `bounded`

- The bounded domain is explicit.
- All harnesses are inventoried.
- Solver/tool version, unwind bounds, assumptions, and results are recorded.
  The receipt's solver equals the registered solver; its harness set and
  unwind-bound key set are identical; and every recorded unwind bound is the
  registered nonzero bound for that harness.
- `bounded_check.assumptions` is required even when empty. It is the exact
  ordered list from the registered model-check unit: every member is a
  nonblank string, duplicate exact strings are rejected, and the compiler
  neither trims, classifies, nor substitutes entries. These execution-model
  assumptions do not silently become project-assumption ledger IDs.
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

Wire strings that are compared or interpreted as machine keys MUST cross the
core boundary through schema-matched validated types, not interchangeable raw
`String` values. In schema version 1 this applies to artifact `logical_name`
and environment-variable `name`: both retain their ordinary JSON-string wire
shape while enforcing the public length and syntax rules during construction
and deserialization. Human-facing labels, tool display names and versions,
command arguments, and diagnostic text remain bounded free text; content
digests, not those labels alone, establish tool or artifact identity.

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
attributed Lean claims, translation symbols, and tests must be inventoried, and
ungated discoveries must fail the build. Inventories are derived from tool
metadata, not source-text scanning (§17).

Adapters communicate with the orchestrator over a versioned JSON subprocess
protocol: requests and responses are schema-validated canonical JSON on
stdin/stdout (`schemas/adapter-protocol.schema.json`), and evidence is
returned either as a complete `proofbound-evidence/2` record or as a strict
`proofbound-adapter-observation/1` execution receipt that the assurance
compiler deterministically enriches with graph and source-closure identities.
The latter prevents a tool adapter from fabricating project provenance it does
not own. Both alternatives are closed schemas; an arbitrary JSON object is not
an evidence boundary. An adapter is therefore any process in any language that
speaks the protocol — future language verticals do not link against the Rust
core, and no adapter couples to a Rust ABI.

The five protocol operations have fixed response meanings; an adapter-specific
interpretation is invalid:

- `doctor` probes the registered tool identity and required capabilities. A
  successful response has `evidence: null` and an empty `inventory`; capability
  discovery is not assurance evidence.
- `inventory` executes the authoritative discovery needed by the route and
  compares it bidirectionally with the registration. A successful response has
  `evidence: null` and the exact nonempty canonical inventory. It does not
  establish that the registered claim check passed. When a route has no
  separate metadata surface — canonical-artifact, independent-check,
  generator, or trusted-transcription — inventory still runs and parses the
  connected checker or reproduction needed to discover the exact set; the
  resulting process facts are deliberately discarded rather than admitted as
  evidence.
- `check` performs discovery and the registered assurance action in a sealed
  copy. Success returns `Passed` evidence plus the same exact nonempty
  inventory and never modifies committed files.
- `reproduce` has the same adapter execution and response contract as `check`,
  but the orchestrator selects one exact unit and bypasses cached evidence.
- `update` is the only write-capable operation and only for a route with an
  explicit output allowlist. It never returns `Passed` evidence; `null` is the
  normal result, while a route-specific `Drifted` record may be returned only
  as non-admissible review information. An update result cannot support a
  claim until a subsequent pinned `check` passes.

Every failed response has `success: false`, `evidence: null`, an empty
inventory, and a bounded stable diagnostic. Successful response inventories
are strict lexical sets: trim-nonempty strings of at most 4096 Unicode
characters, with no Unicode control character, serialized in strictly
increasing order. Exact means equality in both directions with the registered
or tool-derived set; a count, subset, exit status, or source-text scan is not an
inventory.

For Kani, `cargo kani list --format json` must create a fresh `kani-list.json`
that was absent immediately before invocation. The adapter accepts only a
bounded regular file inside the selected package, rejects duplicate raw JSON
keys in the `standard-harnesses` object before any map representation can
collapse them, verifies the metadata totals and tool version, and matches the
nonempty standard-harness set exactly against the registered model-check unit.
Contract harnesses are outside the initial profile and fail closed. `inventory`
stops after this discovery; `check` and `reproduce` additionally run the exact
registered harness vector with its solver and unwind configuration. Kani
`update` is unsupported because the route owns no committed generated output.

An execution observation carries the complete ordered `commands` array and an
equally sized ordered `runs` array. Run `i` has `command_index = i` and binds
that command's exit state, raw stdout/stderr identities, normalized-output
identity, truncation state, and duration. A nonblank `normalization` identifier
names the transformation used before the deterministic-result identity was
computed. The compiler preserves these fields in `proofbound-evidence/2`
provenance instead of selecting a representative command; it also records the
separate typed `reproduction_command`. An unavailable memory observation is
the explicit JSON value `null`, never an invented zero.

Every adapter observation represents actual subprocess execution. When the
assurance compiler turns one into canonical evidence, provenance has
`execution_kind = "observed-processes"`; `commands` and `runs` are both
nonempty and have identical length. Evidence derived wholly inside the
assurance compiler instead has `execution_kind = "compiler-internal"` and
both arrays are empty. Compiler-internal derivation MUST NOT fabricate a
process command or run merely to satisfy a provenance shape. Its separate
typed `reproduction_command`, normalization identity, configuration identity,
timing, budget, and usage remain required so the derivation can still be
reproduced and audited.

A `Passed` observation, or a `Passed` canonical evidence/receipt record whose
`execution_kind` is `observed-processes`, has a nonempty exact inventory. Every
run in such a record has `exit_code = 0` and `output_truncated = false`.
`compiler-internal` evidence has no observed runs and may legitimately have an
empty inventory; the nonempty rule must not invent targets or process facts for
it. Failed, unavailable, and other non-passing records may preserve a partial
or empty inventory and nonzero/truncated run facts for diagnosis, but cannot be
admitted as successful evidence.

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

For artifact linkage it additionally re-encodes the portable
`lean-expr-cbor/1` statement, checks the theorem statement identity, recognizes
only the exact typed binding at the expression root, and joins its literal
claim/path/digest to the checked artifact identity. It does not accept an
adapter projection or Boolean substitute for this derivation.

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
tier = 3

claim_manifests = ["claims/*.toml"]
assumption_manifests = ["assumptions/*.toml"]
evidence_units = ["proofbound/evidence/*.toml"]
translation_units = ["proofbound/translations/*.toml"]
model_check_units = ["proofbound/model-checks/*.toml"]
policy_manifests = ["proofbound/policies/*.toml"]
review_manifests = ["proofbound/reviews/*.toml"]
demo_registry = "proofbound/demos.toml"

[source]
semantic = ["rust/kernel/**", "lean/Allowance/**", "claims/**"]
runner = ["python/**", "Cargo.lock", "lake-manifest.json"]
presentation = ["demo/**", "docs/**"]
external_evidence = ["docs/assurance/reference-audits/**"]

[toolchains]
rust = "rust-toolchain.toml"
lean = "lean-toolchain"
python = ".python-version"
translation = "proofbound/toolchains/translation.lock"

[limits]
max_manifest_bytes = 2097152
max_files = 100000
max_total_bytes = 4294967296
```

The project manifest is strict and rejects unknown fields. `tier` is the
project-wide adoption ceiling from Section 4.3. The manifest arrays are
relative, repository-contained paths or glob patterns for claims, assumptions,
executable evidence units, translation units, model-check units, custom
policies, and regression-review approvals. `demo_registry` is the optional
single registry used by `proofbound demo`.

The four source classes are security-relevant. `semantic` bytes can change a
claim's meaning; `runner` bytes can change how evidence is produced;
`presentation` bytes do not enter semantic closures; and `external_evidence`
names audited material outside normal production semantics that must still be
content-addressed. `[toolchains]` binds optional toolchain descriptor files.
`[limits]` places fail-closed caps on individual manifest bytes, discovered
files, and total closure bytes. Omitted optional collections are empty; omitted
limits use the versioned schema defaults. `schemas/project.schema.json` is the
machine-readable contract and MUST remain field-for-field consistent with this
section.

### 11.2 Claim manifest

```toml
schema = "proofbound-claim/1"
id = "DEMO-TRANSFER-001"
title = "Accepted transfers conserve value"
statement = "For every accepted transfer, debit + credit is conserved."
public_language = "Accepted transfers preserve the combined account value."
formal_declaration = "ProofboundDemo.Transfer.accept_conserves"
statement_encoding = "lean-expr-cbor/1"
statement_sha256 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
foundational_axioms = ["Quot.sound", "propext"]
subject = "rust:allowance-kernel::decide_transfer"
subject_closure = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
profile = "source-refined"
tier = 3
primary_linkage = "refined"

evidence = [
  "translation:transfer-kernel",
  "theorem:transfer-refinement",
  "kani:transfer-bounds",
  "test:cross-language-vectors",
]

assumptions = ["DEMO-IDENTITY-AX-001"]
premises = ["DEMO-U64-REP-001"]
open_obligations = []
out_of_scope = ["Correctness of the pinned compiler and proof-kernel TCB."]
source_roots = ["rust/kernel/**", "lean/Allowance/Transfer/**"]

[bounded_domain]
id = "allowance-request-domain"
description = "The explicitly registered finite request subdomain."
cardinality = 17179869184
ordering_key = [0, 1, 2, 3, 4, 5]
```

Every claim has a stable ID, exact internal `statement`, bound `subject`, trust
`profile`, cited `evidence`, cited `assumptions`, and explicit
`open_obligations` and `out_of_scope` lists. `public_language` is an optional
reader-facing restatement and cannot strengthen `statement`; it never replaces
the internal field. The version-2 compiled release retains `statement` and,
when supplied, `public_language` separately. Its reported claim status carries
the independently derived `public_statement`: `public_language` when present,
otherwise `statement`, with the bounded-domain suffix required by Section
6.3.2 when applicable. All three values are therefore auditable without
presenting rendered language as the registered internal proposition. `tier`
optionally lowers the project ceiling for this claim. `primary_linkage` is
required when more than one valid linkage is present and selects one of
`refined`, `artifact-bound`, `transcribed`, or `model-only`. `premises` names
representation or other dischargeable premises. `source_roots` overrides the
project semantic patterns for the claim and therefore defines the minimum
per-claim closure granularity from Section 11.4. `bounded_domain`, when used,
defines the finite domain language, cardinality, and deterministic ordering
that bounded evidence must match.

The formal-declaration fields are an all-or-none triple. `formal_declaration`
names the compiled Lean declaration; `statement_encoding` names the canonical
encoding; and `statement_sha256` binds the encoded elaborated expression.
`foundational_axioms` is the sorted exact expected transitive foundational
axiom inventory for that declaration; project axioms are mapped separately to
registered assumptions. A missing, extra, or reclassified axiom invalidates
the compiled claim inventory.
`subject_closure` optionally pins a previously reviewed semantic closure and
drift invalidates it. The all-zero digests above are illustrative placeholders,
not admissible reviewed evidence. `schemas/claim.schema.json` is the
machine-readable contract and MUST remain field-for-field consistent with this
section.

`statement_sha256` binds the claim to the bytes produced by
`statement_encoding`, currently the canonical elaborated-expression encoding
`lean-expr-cbor/1` defined in Section 8.2. It never hashes pretty-printer output.
Drift between the manifest digest and the compiled statement — a silently
restated theorem — renders the claim `INVALID`. Subject identity is a
symbol-level binding plus the claim's source closure; Proofbound does not
pretend to bind object code, and says so in the receipt.

Evidence units may use the `python-test` adapter with operation type
`generator` when the same registered program both verifies and deliberately
regenerates committed fixtures. Such a unit is `example-test` evidence only
for its verify-only `check`/`reproduce` execution; `update` returns no evidence.
Its non-empty `outputs` list is a literal, exact write allowlist, every output
is also registered in `inputs` so committed drift invalidates cached checks,
and `expected_inventory` is exactly the output list. For `inventory`, `check`,
and `reproduce`, the adapter creates a fresh candidate project containing the
exact registered non-output inputs and no declared output, invokes the program
with the adapter-owned `--update` switch there, and compares the resulting
complete path-to-bytes inventory with the committed outputs. Verification does
not trust a program's read-only self-report about files already present. A
no-op, missing or extra output, write outside the allowlist, symlink/path
escape, or byte drift fails closed. Only `proofbound update UNIT` runs that
same switch in the orchestrator's sealed update shadow for import into the
reviewed tree. A successful update response therefore carries no evidence
record: regeneration is not assurance evidence.

### 11.2.1 Executable trusted-transcription unit

Trusted transcription uses a deliberately new evidence-unit version; version
1 is not silently reinterpreted:

```toml
schema = "proofbound-evidence-unit/2"
id = "trusted-values"
adapter = "trusted-transcription"
kind = "trusted-transcription"
claims = ["EXAMPLE-TRANSCRIPTION-001"]
tier = 1
binding_mode = "external-round-trip"
expected_inventory = ["source/values.pbtt", "transcribed/values.json"]
inputs = [
  "python/transcription_driver.py",
  "source/values.pbtt",
  "transcribed/values.json",
]
outputs = []
environment_allowlist = ["PATH"]

[operation]
type = "transcription"

[transcription]
schema = "proofbound-trusted-transcription/1"
source = "source/values.pbtt"
committed_transcription = "transcribed/values.json"
driver = "python/transcription_driver.py"
source_format = "proofbound-u32-lines/1"
transcribed_format = "proofbound-u32-json/1"
driver_abi = "proofbound-transcription-driver/1"

[resource_budget]
time_seconds = 60
disk_bytes = 67108864
memory_bytes = 268435456
```

`proofbound-evidence-unit/2` is reserved for this exact route. It requires the
adapter, evidence kind, operation, binding, and nested schemas shown above.
Conversely, `/1` forbids the transcription block and all three new typed enum
values; an old generic checker cannot relabel itself as trusted transcription.
All unrelated operation fields and evidence qualifiers are absent or empty:
there is no theorem, evaluation mode, bounded domain, configured argument,
checker path, package, target, manifest, inventory file, premise, or
assumption. The environment allowlist is exactly `["PATH"]`: the adapter needs
it to resolve `python3`, hashes and binds its value in provenance, and records
the resolved Python executable identity. No other parent environment enters
the driver process.

The three transcription paths are distinct, repository-relative exact file
paths, not globs; each is at most 4096 printable-ASCII bytes and obeys the
reserved-component rules of Section 11.3. The driver ends in `.py`.
`inputs` is exactly the lexically sorted set of source, committed
transcription, and driver. `expected_inventory` is exactly the lexically
sorted set of source and committed transcription. `outputs` is empty because
neither `check` nor this evidence kind owns a committed write. The two format
identifiers are distinct, at most 128 bytes, and use the versioned grammar
`^[a-z][a-z0-9]*(?:[-_.+][a-z0-9]+)*/[1-9][0-9]*$`.

The fixed `proofbound-transcription-driver/1` ABI consists of exactly these two
commands, in order, under the evidence unit's declared budget:

```text
python3 DRIVER transcribe --source SOURCE --output FRESH_CANDIDATE
python3 DRIVER reencode --transcription FRESH_CANDIDATE --output FRESH_REENCODED
```

The adapter owns every argument after the driver path; the manifest cannot add
arguments. Both commands run in one sealed shadow with the same registered
driver. The re-encoder consumes the freshly produced candidate, not the
committed transcription. This connected execution prevents two unrelated
comparisons from being presented as one round trip. The adapter requires all
of the following:

1. the fresh candidate equals the committed transcription byte-for-byte; and
2. the fresh re-encoding equals the source byte-for-byte.

The observation carries a strict nested
`proofbound-trusted-transcription/1` record containing the source, committed
transcription, fresh candidate, fresh re-encoding, and driver artifact
identities; both format IDs; the fixed ABI; and the distinct transcriber and
re-encoder role identities. Its input artifacts are the exact sorted manifest
input set. Its generated artifacts are exactly, in lexical order,
`trusted-transcription/<unit-id>/reencoded-source` and
`trusted-transcription/<unit-id>/transcribed-candidate`. No transcription-
specific or driver-authored success/binding Boolean, and no TCB node ID,
exists in the nested observation or manifest; the generic protocol outcome is
derived from execution and comparison results.

The compiler admits that observation only when every registered path, format,
inventory member, and artifact identity matches. The canonical version-2
evidence record then retains the five artifact identities and two derived role
records under its nested `proofbound-trusted-transcription/1` value. Each role
identity is independently recomputed from canonical `{abi, driver, role}`
content under the `proofbound-transcription-tcb-role/1` digest domain. The
compiler derives the distinct node IDs
`tcb:trusted-transcription:<unit-id>:transcriber` and
`tcb:trusted-transcription:<unit-id>:reencoder`, where `<unit-id>` is the
manifest ID without a `unit:` prefix. Their TCB-ledger names are respectively
`trusted-transcription/<unit-id>/transcriber` and
`trusted-transcription/<unit-id>/reencoder`; each ledger version is the fixed
ABI `proofbound-transcription-driver/1`, and its identity is the corresponding
derived role digest. These remain separate even when one driver implements
both roles. The independent verifier repeats the derivation and both byte-
identity comparisons. A passing record yields only `TRANSCRIBED` linkage. It
cannot yield `PROVED`, `ARTIFACT_BOUND`, or `REFINED`.

`schemas/evidence-unit.schema.json`,
`schemas/adapter-observation.schema.json`, `schemas/evidence.schema.json`, and
`schemas/receipt.schema.json` are the closed machine-readable contracts for
this route and MUST remain field-for-field consistent with this section.

### 11.3 Translation unit

```toml
schema = "proofbound-translation-unit/3"
id = "transfer-kernel"
pipeline = "charon-aeneas"
generated_dir = "lean/Generated/Transfer"
handwritten_refinement = "lean/Allowance/TransferRefinement.lean"
determinism_runs = 2
determinism_normalization = "pretty-printed-llbc/1"
forbid_generated_axioms = true
claims = ["TRANSFER-001"]

[[external_bridges]]
# Hand-authored external function/type models. They live outside the
# generator-owned tree, are declared explicitly, and are byte-pinned.
file = "lean/Bridges/TransferExternal.lean"
module = "Bridges.TransferExternal"
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
# Typed vocabulary: upstream-sorry | upstream-sorry-ax.
kind = "upstream-sorry"

[[invocations]]
id = "allowance-kernel"
cargo_package = "allowance-kernel"
# This is the exact package manifest and contains the literal
# `[package].name = "allowance-kernel"`; virtual workspace manifests do not
# satisfy an invocation.
cargo_manifest = "rust/kernel/Cargo.toml"
crate_name = "allowance_kernel"
# Relative to this invocation's isolated LLBC directory; never committed.
llbc_file = "allowance_kernel.llbc"
start_from = ["allowance_kernel::decide_transfer"]
opaque = []
include = []
aeneas_subdir = "Transfer"

[[invocations.translated_closure]]
kind = "function"
rust_name = "allowance_kernel::decide_transfer"

[[invocations.translated_closure]]
kind = "function"
rust_name = "allowance_kernel::{allowance_kernel::Decision}::denied"

[[invocations.translated_closure]]
kind = "type"
rust_name = "allowance_kernel::Decision"

[[invocations.translated_closure]]
kind = "type"
rust_name = "allowance_kernel::DecisionCode"

[[invocations.translated_closure]]
kind = "type"
rust_name = "allowance_kernel::Request"

[[invocations.outputs]]
kind = "lean-source"
# `produced` is relative to the Aeneas `-dest` root. Lean outputs include the
# declared Aeneas subdirectory.
produced = "Transfer/Funs.lean"
destination = "lean/Generated/Transfer/Funs.lean"

[[invocations.outputs]]
kind = "lean-source"
produced = "Transfer/Templates.lean"
destination = "lean/Generated/Transfer/Templates.lean"

[[invocations.outputs]]
kind = "translation-report"
# Aeneas emits its report at the `-dest` root, outside `aeneas_subdir`.
produced = "translation.json"
destination = "lean/Generated/Transfer/translation.json"

[import_mapping]
mode = "external-source-root"
source_roots = ["lean"]

[resource_budget]
time_seconds = 1800
disk_bytes = 26843545600
memory_bytes = 8589934592
```

Version 3 is deliberately breaking. Version 2 made invocations and output maps
authoritative but recorded only selector roots, so it could prove that a root
was present without binding the full transitive local closure emitted by the
translator. Version 3 adds the required typed `translated_closure`; the adapter
must reject version 2 rather than infer this security-relevant inventory.

`pipeline` is the typed `charon-aeneas` pipeline. `invocations` is a non-empty,
strictly ID-sorted sequence, and its order is execution and receipt order. Each
invocation declares the exact Cargo package and repository-relative package
`Cargo.toml`, whose literal `[package].name` MUST equal `cargo_package`, Rust
crate name, run-workspace-relative `.llbc` file, start, opaque, and included
selector inventories, the exact typed `translated_closure`, optional Aeneas
subdirectory, and complete output map. Selector inventories are strict sorted
sets of command-safe Rust paths. `start_from` may name a supported local
function or local type, and every root MUST occur exactly once as a non-opaque
local entry in the translation report. Characters that could become
command-line syntax are inadmissible in selectors. Invocation IDs use the
segmented lowercase grammar
`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`. IDs and LLBC paths are unique, and a
`start_from` symbol may occur in only one invocation in a unit. No package,
manifest, crate, LLBC name, symbol, output path, or unit count may be inferred
from another field or embedded in adapter source.

`translated_closure` is the pre-registered complete set of supported,
non-opaque local Rust functions and types that Aeneas is expected to report,
including dependencies reached transitively from `start_from`. Its rows are in
strict `(kind, rust_name)` order, use the typed kinds `function` and `type`, and
may contain Aeneas's printable-ASCII canonical Rust names (including canonical
impl/type syntax) because these values are never command arguments. A Rust name
may occur in only one kind or invocation. The adapter MUST compare the full
typed report closure bidirectionally: an empty, missing, extra, duplicate,
cross-kind, external, opaque, or unsupported root/closure result is not
evidence even when Charon and Aeneas exit zero. External and opaque report
dependencies do not satisfy roots and are outside this supported-local closure;
`opaque` and `include` remain separately typed selector controls. The portable
adapter and receipt inventory is the globally strict-lexical vector of
`function:<rust_name>` and `type:<rust_name>` entries derived from the
registered rows; ordered `start_from` roots remain separately auditable.
Version 3 does not register Aeneas global, trait-declaration, or
trait-implementation inventories. Their report keys are closed and parsed, but
any non-empty such category MUST fail as an unsupported capability rather than
silently omitting generated semantics from the registered closure. Supporting
one requires a versioned typed-inventory extension.

Every invocation maps at least one `lean-source` and exactly one
`translation-report`. Both `produced` and `destination` are safe relative
paths. `produced` is relative to the Aeneas `-dest` root, not to an effective
subdirectory: when `aeneas_subdir` is present, every `lean-source` produced path
is strictly beneath that prefix, while the report remains exactly the root-level
`translation.json`. Mapping rows are in strict `(produced, destination, kind)` order;
produced paths within an invocation and destinations across all registered
units are unique and pairwise prefix-disjoint. Destinations are strictly beneath
`generated_dir` and collectively bounded by both the project's `max_files` and
the fixed 100,000-output translation ceiling. The adapter MUST reject any
emitted file not named by `produced`, any missing mapping, and every
kind/extension mismatch.
It maps bytes without content normalization: `determinism_normalization` names
the exact pretty-printed-LLBC normalization used only for comparing the two
LLBC reproductions. Generated Lean and translation reports are compared and
committed byte-for-byte.

Every translation path is a portable, slash-normalized sequence of non-empty
printable-ASCII components. Backslash, control or non-ASCII bytes, absolute
paths, `.`, `..`, doubled separators, and trailing separators are forbidden,
as are the project-control components `.git`, `target`, `.lake`, `.proofbound`,
`.venv`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, and `.ruff_cache`. The
complete UTF-8 encoding is at most 4096 bytes. Printable ASCII is a deliberate
cross-platform choice: it makes the JSON Schema character bound and the runtime
byte bound identical. A unit has at most 4096 invocations, claims, and entries
in each start/opaque/include list; at most 1024 source roots, external bridges,
and template-axiom entries; and at most 4096 warning entries.
An invocation maps at most 100,000 outputs, subject to the smaller aggregate
limit above. Translation and exact Cargo package TOML files obey the project's
`max_manifest_bytes`. Generated artifacts, external bridges, and their complete
inventories are bounded by the declared disk budget and project
`max_total_bytes`; adapters MUST NOT impose a smaller undocumented per-file
ceiling.

Hand-reviewed external bridges remain byte-pinned. Translator template axioms
must stay uncompiled with exact per-file counts, and upstream warnings must be
inventoried so new warnings fail rather than scroll past. Every template or
warning artifact MUST itself be a mapped `lean-source` destination; a side
inventory cannot smuggle an undeclared generated file into the closure.
Bridge `module` identities are unique within a translation unit. Warning
`kind` is the closed vocabulary `upstream-sorry` or `upstream-sorry-ax`, exactly
the two scanners implemented by the reference adapter; accepting an
unimplemented free-text warning kind would create an unexecutable manifest.

`generated_dir` is exclusively generator-owned. A generated module MAY import
a declared handwritten external bridge, but the bridge path MUST be outside
`generated_dir`. `check` rejects extra, stale, missing, renamed, and changed
files. For `update`, `generated_dir` is the explicit recursive deletion and
atomic-replacement boundary, while mapped destinations are the exclusive
creation/modification allowlist inside the replacement. Thus update may delete
stale files only inside that validated non-symlink boundary, may install only
the exact map, and never asks an adapter to write the committed tree. No
handwritten source or review note may depend on preservation by cleanup.

Out-of-tree bridges need explicit import support, because translators emit
imports expecting external models inside their own output namespace. The
implemented `external-source-root` mode declares a non-empty, sorted set of
repository-relative source roots. Every root must exist as a directory in the
sealed shadow, may be an ancestor but not equal to or beneath `generated_dir`,
and every bridge's required `module` MUST resolve from exactly one root as
`<root>/<module components>.lean` to the bridge's declared `file`. These roots
are a typed import-resolution contract; they are not extractor selectors and
MUST NOT be passed through an invented Aeneas option. `audited-rewrite` remains
a reserved spelling but is rejected until a typed rewrite implementation,
digest domain, and adversarial corpus exist. Silent import rewriting or
hand-editing generated output is not supported.

A source-refinement evidence unit using this manifest has no committed
`outputs` and no `expected_inventory`: adapters return observations from a sealed shadow, while only
`proofbound update` owns committed writes. Its operation manifest, flattened
ordered start inventory, claims, and resource budget MUST exactly equal the
registered version-3 translation unit. The manifest and generated tree are
automatic cache inputs. The handwritten refinement, every external bridge, and
the existence or absence of every bridge-module candidate under every declared
source root are automatic cache inputs as well. Omission from a manually
curated input list cannot make their drift or an ambiguous new module invisible.

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

Lists of invocations, packages, Cargo manifests, crate and LLBC identities,
symbols, produced files, generated destinations, external bridges, and claim
mappings MUST live in manifests rather than orchestration source code.

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

### 11.5 Version-2 evidence and release receipt semantics

`proofbound-evidence/2`, `proofbound-compiled-release/2`, and
`proofbound-release-envelope/2` are a coordinated wire transition. Version 1
records are not silently reinterpreted under these rules.

The canonical evidence record has these additional fidelity requirements:

- `bounded_check.assumptions` is a required array. It preserves the registered
  model-check unit's strings exactly and in order, including the distinction
  between an empty array and a missing field. Every string is nonblank and
  exact duplicates are invalid. During assurance compilation the producer
  compares the array with the registered model; the portable release does not
  claim to embed that complete external registration.
- `resource_usage.peak_memory_bytes` is required and nullable. A nonnegative
  integer is a measurement, including the legitimate measurement zero;
  `null` means not measured. The declared memory budget remains a required
  nonnegative integer and is not a substitute for observed usage.
- `provenance.execution_kind` is required. For `observed-processes`,
  `provenance.commands` preserves every observed typed command in execution
  order; `provenance.runs` has the same nonzero length and order, and run `i`
  has `command_index = i`. Each run carries required nullable exit status, raw
  output identities, normalized-output identity, truncation state, and
  duration. No command or run may be collapsed into a representative summary.
  For `compiler-internal`, both arrays are empty because no subprocess was
  observed; inventing a process record for an internal derivation is invalid.
  For both kinds, `provenance.normalization` is a required nonblank identifier
  and `provenance.reproduction_command` remains a separate required typed
  command.
- A `passed` record with `execution_kind = "observed-processes"` has a
  nonempty, duplicate-free exact `inventoried_targets` set. Every retained run
  has exit code zero and untruncated output. The condition is deliberately the
  conjunction: a passed `compiler-internal` derivation may have an empty
  inventory because it observed neither a process nor tool-selected targets.
  Non-passing records may retain empty or partial inventory and failed run
  facts for diagnosis; those facts never support claim admission.

The compiled release keeps a claim's required internal `statement` and its
optional `public_language` as distinct fields. Each reported claim status
contains the required derived `public_statement` described in Section 6.3.2.
The independent verifier recomputes that rendered field from the retained
claim inputs and rejects substitution or drift.

The producer's private compiled-state boundary advances at the same time to
`proofbound-compiled-project/2`, and claim-input identities use the
`proofbound-claim-input/2` domain. Reporting and release commands MUST reject
version-1 compiled state and require a fresh `proofbound check`; otherwise an
evidence-free legacy ledger claim could be released after its internal
statement had already been replaced by reader-facing language.

The closed public schemas in `schemas/evidence.schema.json`,
`schemas/receipt.schema.json`, and
`schemas/adapter-observation.schema.json` are the machine-readable contracts
and MUST remain field-for-field consistent with these rules. Cross-field rules
that JSON Schema cannot express — exact model-registration equality, aligned
command/run lengths and positions, and derivation of rendered language — are
validated by the producer and, where the portable receipt contains both sides,
independently by `proofbound-verify`.

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
proofbound release [--output DIR]
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

When a command accepts `--json`, failures are emitted as the strict
`proofbound-error/1` envelope in `schemas/error.schema.json`. Every field above
is present in the envelope; fields that do not apply are `null` or an empty
list rather than being omitted. Human output carries the same stable code and
remediation. An unexpected internal error uses the reserved `PB-CLI-0001`
fallback and MUST NOT be presented as a domain-specific validation result.

## 13. Initial repository structure

The project SHOULD begin with:

```text
proof-bound/
├── .cargo/
│   └── config.toml              # locked cargo xtask alias
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
│   ├── proofbound-adapter-test/
│   └── xtask/                    # typed, cheap-first repository gate runner
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
│   ├── evidence-unit.schema.json
│   ├── evidence.schema.json
│   ├── assumption.schema.json
│   ├── policy.schema.json
│   ├── review.schema.json
│   ├── translation-unit.schema.json
│   ├── model-check-unit.schema.json
│   ├── translation-toolchain-lock.schema.json
│   ├── mutation-registry.schema.json
│   ├── adapter-protocol.schema.json
│   ├── adapter-observation.schema.json
│   ├── closure.schema.json
│   ├── demo-registry.schema.json
│   ├── error.schema.json
│   ├── graph.schema.json
│   ├── report.schema.json
│   ├── tcb.schema.json
│   ├── lean-expr-v1.cddl
│   └── receipt.schema.json
│
├── templates/
│   ├── artifact-checker/
│   ├── rust-aeneas-refinement/
│   ├── trusted-transcription/
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
time, so the complete audit subjects are pinned:

- **Auths Proof:** commit
  `95c9d4583e10fdc3ffaecc0a96790bec1c922640`; translation source-closure
  digest `616fcfae33e76019a1e9c59dfc886375b8e2f92dbf381fb2074a7df7bfa5f741`;
  SHA-256 of the canonical closure record
  `formal/qualification/aeneas/source-closure.json`:
  `9bb83f20310acee4edbeb0b78ec2474171789e1cc976b7fc34b742e2335fdacc`.
- **Matrix Math:** commit
  `fb7afc70b27bbbf5c3cb8fde61e9d9acb482501d`; canonical source-closure
  digest `7c47b198db3e279bf21f3839c877a851fefd23e475c4277f7dcd93dc22719048`.

Abbreviated revisions are insufficient audit identities. A reference audit
MUST pin the full revision plus either a durable, content-addressed source
archive or a canonical closure record that enumerates and hashes every audited
file. A closure digest identifies bytes but does not make them retrievable. In
particular, Matrix Math has no remote: before the local history can be treated
as disposable, the exact audited closure MUST be sealed in Proofbound's CAS or
another durable archive and that archive's digest added to this record. Until
then, the audit is reproducible only from the retained local clone, and this
caveat is part of the evidence rather than a footnote to be dropped.

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
| Quarantined generated Lean | extract | With one correction: Proofbound moves hand-authored external bridges outside the generator-owned tree, declares and byte-pins them independently, and permits generated modules to import them (§11.3). They are never discovered by convention or preserved inside a replaceable output directory. |
| Representation-premise registration | extract | Elevated to a normative status rule (§6.3.2). |
| Handwritten refinement theorem registration | extract | |
| Kani harness inventory and ungated-harness rejection | redesign | The reference gate is a package-level textual scan for `#[kani::proof]`; a `cfg_attr`-wrapped or reformatted attribute escapes it, and no per-harness registry exists. Proofbound requires a per-harness inventory derived from tool metadata (e.g. `cargo kani list`), matched bidirectionally against the manifest. |
| Claim-to-evidence compliance inventory | redesign | The reference theorem inventory is a hand-maintained literal list covering a fraction of public claims. Proofbound enumerates compiled declarations carrying `@[proofbound_claim "…"]` and matches that attributed public-claim set bidirectionally against manifests. Helper declarations are intentionally outside the inventory (§8.2, §17). |
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
- every exact typed command in execution order, its aligned run record, and
  the nonblank normalization identifier;
- a separate exact typed reproduction command;
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
- adapters report actual cost in receipts so budgets stay honest; an unknown
  peak-memory observation is required as `null`, while numeric zero means a
  measured zero-byte peak; and
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
- reject unregistered attributed Lean claims, Kani harnesses, and translation
  units — for Lean, by matching compiled declarations carrying the
  `proofbound_claim` attribute bidirectionally against the registered public
  claim inventory rather than by source-text scanning or inventorying helper
  declarations; for Kani, by per-harness tool-metadata inventory rather than
  attribute grep;
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

Repository implementations may group these stages behind a typed development
runner such as `cargo xtask ci`, but the ordering and trust boundary remain
visible and testable. Cheap deterministic checks — formatting, linting,
schemas, unit tests, and a proof-free release/verifier round trip — run before
costly registered proof or model-check units. A full gate executes the fresh
assurance compilation only once; release reproduction consumes those same
receipts, and the standalone verifier remains the last process that decides
success. Shell snippets are not used to construct adapter or release command
arguments or temporary paths.

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

`tcb-ledger.json` uses schema `proofbound-tcb-ledger/1`. Its sorted unique
`components` array contains the exact `{ name, version, identity_sha256 }`
identity of every tool and adapter named by released evidence; it does not
invent a component category or rationale that the underlying receipt did not
record. The independent verifier parses this ledger strictly and requires its
component set to equal the union recomputed from evidence provenance. A
missing, extra, duplicate, malformed, or conflicting component invalidates the
release.

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
  from the two original demos plus the reference-repository study; migrate
  both original demos onto the extracted core.
- Build `proofbound-verify` (§10.4) against the same specification with no
  shared source, plus the registered synthetic-graph corpus that
  cross-checks the two derivations.
- Acceptance: both original demos run through the shared core with no demo-
  specific logic in core source; synthetic graph tests prove no status can be
  upgraded by omitting evidence or assumptions — in both implementations;
  `init` produces a working Tier 0 ledger on an arbitrary existing
  repository, not only on the demos; every extracted abstraction carries a
  case record naming its two consumers.

### M4: adapter hardening

- Manifest-driven Charon/Aeneas invocation (the Section 11.3 inversion),
  compiled declaration/axiom audit applied to all generated modules,
  per-harness Kani inventory, unregistered-attributed-claim rejection,
  deterministic regeneration, and source closures.
- Acceptance: the allowance kernel is translated and refined purely from
  manifests; an ungated harness, attributed public theorem missing from the
  claim inventory, manifest claim missing its compiled attribute, or generated
  axiom fails closed. Unattributed helper lemmas do not require claim records.

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
