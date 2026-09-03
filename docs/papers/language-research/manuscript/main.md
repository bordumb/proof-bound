---
title: "From Passed to Justified: The Proofbound Assurance-Language Research Programme"
author: bordumb
date: 3 September 2026
abstract: |
  Software assurance is normally assembled after the fact from continuous-
  integration jobs, test reports, analyzers, model checkers, proof assistants,
  build logs, and policy gates. These systems can each be useful while their
  composition remains epistemically unsafe: a shared word such as *passed*
  does not state what was quantified, which artifact was examined, which
  assumptions remain, who had authority to report the fact, or whether a
  publication policy actually consumed it. This paper reports the current
  Proofbound research programme on a language for making those distinctions
  explicit. Its proposed semantic centre is a canonical, backend-neutral
  Assurance IR with a closed evidence algebra, typed identities and
  dependencies, independently checkable derivation traces, and publication
  decisions that are derived rather than asserted.

  The evidence is deliberately bounded. Experiment 0005 remains open: its
  latest checked-in audit completes 11 of 16 losslessness rows and leaves five
  partial. Within that programme, independent Rust and Python prototypes agreed
  on 20 positive cases, rejected 20 adversarial cases with the expected codes,
  and agreed on 15 domain-hash vectors; a later projection covered all 45
  captured portable records while preserving two property records as legacy
  sampling. Experiment 0006 showed, for Hypothesis and fast-check, that an
  adapter-owned driver can preserve a sampling contract and rejected ten
  registered attacks. Experiment 0007 falsified that contract's three-framework
  generality on proptest because RNG algorithm and authoritative counter
  availability differ. Experiment 0008 validated a layered replacement over
  three frameworks and twelve attacks. Experiment 0009 generated 500 valid and
  500 single-mutation adversarial derivation programs; the independent
  implementations had zero disagreements over eleven closed rules and sixteen
  attack classes. These checks do not prove the algebra complete or correct.
  They support continuing semantic and invalidation research before either a
  final assurance DSL or native executable language is justified.
---

# 1. Introduction

A software release can pass every configured gate while leaving the central
question unanswered: *what, precisely, is now justified?* A unit test establishes
that one registered execution produced an expected observation. A sampled
property establishes that a generator and predicate completed a finite campaign
under particular controls. A bounded model checker establishes a proposition
within recorded bounds and assumptions. A proof assistant may check a universal
theorem in a formal model. A reproducible build establishes byte identity across
executions. None of these facts, alone, establishes all the others.

In contemporary development these facts are distributed among workflow files,
tool-specific reports, source annotations, artifact stores, and dashboards.
Composition is typically performed through booleans, job dependencies, and
prose. That representation is too weak for assurance: it can hide quantifier
changes, confuse a model theorem with a property of shipping bytes, omit an
execution-relevant parameter, or report missing diagnostic telemetry as if a
claim had weakened. Specification 0001 therefore treats formal standing,
subject linkage, and assumption burden as separate facets and makes status a
derived output rather than an adapter-authored label [@proofbound-spec].

The Proofbound language research programme asks whether this discipline can be
given a compact language-independent semantics and, only later, a useful authoring
and programming language [@proofbound-programme]. Its current direction is not
a claim that a language exists. It is a sequence of falsifiable studies: first
extract meaning from existing Python, TypeScript, Rust, Lean, Kani, Aeneas, and
release records; then test a closed algebra and invalidation semantics; then
compare authoring surfaces and effect models; and only after those gates consider
a native executable subset.

This paper makes four contributions. First, it states the research problem as a
provenance-preserving composition problem, not as a request for another test
runner or proof assistant. Second, it presents the candidate system model:
claims, subjects, assumptions, evidence, typed facts, derivations, policies,
artifacts, and publication decisions in a canonical Assurance IR. Third, it
synthesizes the checked-in results of Experiments 0005--0009 with exact corpus
sizes, result artifacts, and limits. Fourth, it analyzes the Tower-of-Babel risk
and gives an adoption path in which existing-language adapters remain primary
until the data justify native syntax or execution.

The terminology is intentionally strict throughout. *Proof* refers only to an
appropriately checked theorem. Tests, static analyses, randomized sampling,
mutation witnesses, finite enumerations, and bounded model checks are evidence,
but they are not described as proofs. A theorem about a model is not described
as a shipping claim without a registered correspondence to the relevant source
or artifact.

# 2. Motivation

## 2.1 Fragmentation is a semantic problem

The conventional pipeline is organized around tools. CI invokes a test runner,
type checker, model checker, prover, packager, scanner, and policy step; each
reports success in its own schema. A green workflow answers whether the configured
commands returned an accepted process outcome. It does not necessarily preserve
the claim, inventory, sampling regime, formal proposition, correspondence,
assumptions, or exact published artifact associated with that outcome.

This is not merely a user-interface defect. Three kinds of information loss are
structural.

1. **Strength loss.** Unlike evidence families collapse into `passed`. A sampled
   observation can then be retold as a universal guarantee; a static consistency
   check as functional correctness; or a bounded result without its bounds.
2. **Identity loss.** Tool names, filenames, or raw digests substitute for typed
   identities. The relevant relation may require a logical artifact name, digest,
   byte size, proposition identity, inventory, subject closure, and policy ID at
   once.
3. **Authority loss.** A value may be registered, observed, reviewed, derived,
   or unavailable. Flattening those origins permits configuration to masquerade
   as observation, a derived counter to masquerade as a measured one, or absence
   to masquerade as zero.

The repository supplies concrete instances. In EXP-0006, Vitest emitted strict
JSON saying that an outer test node passed, yet that JSON omitted the nested
fast-check seed, run count, generator identity, skip count, shrink count, and
effective configuration. Hypothesis printed useful counts as terminal prose but
did not emit the closed machine report required by the preregistration. Neither
route could establish the proposed sampling contract merely from ordinary runner
output [@proofbound-exp0006]. Likewise, EXP-0005 found that locating an executable
and reading its version did not establish readiness: sealed npm execution also
needed dependency-fetch authority, while Lean evidence needed compiled project
modules (`docs/experiments/0005-assurance-ir-extraction/captures/q1-completion-r1/index.json`).

## 2.2 Notification fatigue follows from tool-oriented state

Tool-oriented reporting makes every missing field or failed job look locally
important. Assurance decisions are claim-oriented: an unavailable fact matters
when a registered derivation consumes it. The distinction is precise. If an
empirical-admission rule requires a completed-case count, making that count
unavailable blocks the conclusion. If the same rule does not consume shrink
telemetry, the absence of that telemetry should remain recorded but should not
generate an admission alert. EXP-0008 and EXP-0009 exercise exactly this pair of
cases; both independent implementations distinguished them [@proofbound-exp0008;
@proofbound-exp0009].

The programme therefore treats reduced notification volume as a future empirical
hypothesis, not an implemented benefit. Current prototypes establish only that
the data model and rules can represent consequence-indexed absence in finite
corpora. Whether this improves human decisions without hiding important signals
is reserved for structured user study (Hypothesis H6 and workstream WS-UQ in
`docs/research/proofbound-language/`).

## 2.3 The target: an account of justification

The proposed language is best understood as a language for *accounts of
justification*. For claim $c$, a publication decision should be reproducible from
the exact registered programme $P$, evidence facts $E$, derivation trace $D$, and
policy $\pi$:

$$
  \operatorname{publish}(c) =
  \operatorname{check}_{K}(P, E, D, \pi),
$$

where $K$ is a small independent checker. The producer may discover evidence,
run expensive tools, or search for proofs. It may not author the final status.
The result is not a scalar confidence score. It is a structured judgment with
separate formal, linkage, assumption, and policy information.

# 3. Related Work

## 3.1 Proof assistants and proof-carrying computation

Lean combines a programming language with an interactive theorem prover and a
small kernel that checks elaborated proof terms [@demoura2021lean4]. Proof-carrying
code and certifying algorithms similarly separate a potentially complex producer
from a simpler consumer that checks a witness [@necula1997pcc;
@mcconnell2011certifying]. Proofbound adopts this producer--consumer discipline
for assurance derivations. It does not replace the prover: the Assurance IR must
record the theorem, assumptions, evaluation mode, and correspondence needed to
use prover output in a release decision.

The difference in level is central. A proof assistant answers whether a theorem
follows in a formal environment. The assurance language must additionally answer
which registered software claim cites that theorem, what subject it concerns,
whether production source or bytes correspond to the model, which policy admits
it, and which residual assumptions remain. A model theorem stays `MODEL_ONLY`
without the distinct correspondence evidence required by the specification.

## 3.2 Verus, refinement systems, and translation

Verus integrates executable Rust, specifications, ghost state, and SMT-backed
verification [@lattuada2024verus]. Refinement-type systems such as Liquid Types
enrich program types with logical predicates and automate important proof
obligations [@rondon2008liquid]. Aeneas instead translates a Rust subset into
functional code for interactive theorem provers [@ho2022aeneas]. These systems
can establish program properties more directly than an assurance orchestrator.

Proofbound's proposed role is orthogonal and compositional. Verus, Lean, Aeneas,
or a future verified compiler can be a proof-producing backend, but their outputs
enter through a typed boundary. The Assurance IR preserves proposition identity,
tool and trusted-base identity, assumptions, translated inventory, and the
correspondence actually established. It also composes that formal evidence with
empirical evidence, artifact reproduction, and publication policy. The native
language proposal is subject to a stop condition: if a small Verus, Lean, or
Dafny component integrated through Proofbound is equally strong and simpler,
native expansion should stop (`workstreams/native-runtime.md`).

## 3.3 Build systems and CI configuration

Build systems formalize tasks, dependencies, scheduling, and rebuild decisions;
their design space includes static and dynamic dependencies and several kinds of
rebuild strategy [@mokhov2018build]. CI configuration composes such tasks with
remote execution and reporting. Proofbound also needs dependency and cache
semantics, but its equivalence relation is stricter: reuse is valid only when the
typed semantic and execution dependencies that justify an evidence fact remain
equivalent. A cached process success is not interchangeable with evidence about
a different claim, inventory, artifact, tool, assumption, or policy.

Nor is Proofbound intended to schedule every build. The proposed kernel checks
meaning and derivation after adapters normalize observations. Existing build and
CI systems remain execution substrates. Their logs and attestations become inputs,
not the semantic definition of `TESTED`, `PROVED`, `ARTIFACT_BOUND`, or
publication.

## 3.4 Policy languages and assurance cases

Authorization languages such as Cedar decide whether principals may perform
actions on resources and are designed for analyzable policy evaluation
[@cutler2024cedar]. Assurance cases, including Goal Structuring Notation, organize
claims, arguments, and evidence [@kelly2004gsn], while Assurance 2.0 emphasizes
explicit defeaters and disciplined argument [@bloomfield2021assurance2]. These
are close intellectual relatives, but the intended judgment differs. Proofbound
policy does not decide an application request and cannot change evidence strength;
it selects which already-derived judgments permit publication. The IR also binds
canonical bytes, source closures, cache inputs, and executable provenance, then
requires a second implementation to replay the derivation.

Supply-chain systems such as in-toto bind steps and artifacts to actors and
layouts [@torresarias2019intoto]. Such provenance is necessary but does not by
itself state what behavioral proposition an artifact satisfies. Conversely, a
source theorem without artifact correspondence supplies behavioral meaning but
not a shipping-byte claim. Assurance IR attempts to represent the join rather
than substituting either side for the other.

# 4. Research Questions

The programme defines stable hypotheses H1--H8 in
`docs/research/proofbound-language/hypotheses.md`. Only H1 and H2 are currently
under test; no programme-level hypothesis is recorded as passed. This paper
groups the present work into six research questions.

| ID | Question | Current evidence boundary |
|---|---|---|
| RQ1 | Can existing routes compile into a smaller backend-neutral IR without semantic loss? | EXP-0005; still open, 11/16 losslessness rows complete |
| RQ2 | Can unlike evidence remain a closed algebra with forbidden strength coercions? | Bounded passes in EXP-0005, EXP-0008, and EXP-0009 |
| RQ3 | What must a portable sampled-property contract retain? | EXP-0006 positive result, EXP-0007 falsifying holdout, EXP-0008 layered replacement |
| RQ4 | Can complete derivations be backend-independent and independently checked? | EXP-0009, six routes and 500/500 generated corpus |
| RQ5 | Can unavailable facts be reported according to their consequences? | Finite attacks in EXP-0008 and EXP-0009; no human study yet |
| RQ6 | Can migration, cache, artifact, provenance, policy, and invalidation joins fail closed? | Partial evidence in EXP-0005; dedicated invalidation experiment not yet run |

The questions are intentionally asymmetric. A corpus pass can support a design
for its registered domain; one counterexample can falsify a proposed general
contract. EXP-0007 is therefore as informative as the later positive result: it
prevents a two-framework abstraction from being promoted as a universal one.

# 5. System Model

## 5.1 One kernel, several producers and surfaces

The candidate architecture separates authoring, evidence production,
normalization, derivation, and publication. Figure 1 shows the intended trust
direction. Tool-specific adapters may be numerous; constructors and derivation
rules in the common kernel must remain few and versioned.

\begin{figure}[H]
\centering
\begin{tikzpicture}[node distance=8mm and 9mm]
  \node[compsolid=gblue] (toml) {Existing programmes\\TOML / current receipts};
  \node[compsolid=gpurple, right=of toml] (dsl) {Future assurance DSL\\native frontend};
  \node[comp=ggreen, below=of toml] (adapters) {Typed adapters\\Python / TypeScript / Rust\\Lean / Kani / Aeneas};
  \node[comp=gpurple, below=of dsl] (compiler) {Frontend compiler\\and proof automation};
  \node[trust=gblue, below=13mm of $(adapters)!0.5!(compiler)$] (ir) {Canonical Assurance IR\\claims · facts · artifacts · policy\\closed derivation traces};
  \node[trust=gred, below=of ir] (kernel) {Independent checker\\decode · join · derive · decide};
  \node[compsolid=gamber, below=of kernel] (out) {Status facets · blockers\\publication decision · receipt};
  \draw[flow=ggreen] (toml) -- (adapters);
  \draw[flow=gpurple] (dsl) -- (compiler);
  \draw[flow=ggreen] (adapters) -- (ir);
  \draw[flow=gpurple] (compiler) -- (ir);
  \draw[flow=gred] (ir) -- (kernel);
  \draw[flow=gamber] (kernel) -- (out);
\end{tikzpicture}
\caption{Candidate architecture. Backend-specific knowledge is permitted at typed conversion boundaries, not in common status derivation. The DSL and native frontend are proposals, not implemented production surfaces.}
\end{figure}

The checked-in production verifier already demonstrates a narrower version of
the independence requirement. `crates/proofbound-verify/Cargo.toml` explicitly
has no dependency on another `proofbound-*` crate; it decodes a closed receipt
format and recomputes status without executing evidence backends. The research
prototype is separate: `crates/proofbound-ir-prototype/` implements producer-side
projection and candidate algebra checks, while
`python/proofbound/assurance_ir_checker.py` is independently written and does
not import the Rust types [@proofbound-exp0005; @proofbound-exp0009].

## 5.2 Claims, facets, assumptions, and policy

Let a claim be

$$
c = (i, s, m, e, a, x, \pi),
$$

where $i$ is a stable claim identity, $s$ a typed subject and closure, $m$ the
machine meaning, $e$ cited evidence identities, $a$ assumptions and premises,
$x$ exclusions or open obligations, and $\pi$ the selected policy. Reader-facing
language is represented separately from $m$ so presentation cannot silently
replace machine meaning.

Production Proofbound reports three independent facets [@proofbound-spec]:

$$
\operatorname{status}(c) = (F(c), L(c), A(c)).
$$

- $F$, formal standing, distinguishes `OPEN`, `TESTED`, `BOUNDED_CHECKED`,
  `PROVED`, and invalid states.
- $L$, linkage, distinguishes `MODEL_ONLY`, `TRANSCRIBED`, `REFINED`, and
  `ARTIFACT_BOUND`.
- $A$, assumption burden, is `NONE` or an explicit `ASSUMED` set.

Policy consumes these facets and additional named requirements to produce an
admission or publication decision. It cannot reinterpret `TESTED` as `PROVED`,
erase an assumption, or turn `MODEL_ONLY` into `ARTIFACT_BOUND`. This separation
is also why the EXP-0009 research algebra must not be mistaken for full
production parity: its bounded six-route slice uses a smaller formal-facet
vocabulary and models its bounded-check route as `tested`; its own scope excludes
complete production-rule parity.

## 5.3 Closed evidence algebra

The draft Assurance IR (`docs/research/proofbound-language/assurance-ir-v1.md`)
uses a closed sum rather than a common success record with optional details.
Table 2 summarizes the intended meanings. Names are research constructors, not
a frozen wire contract.

| Constructor | What it can establish | What it cannot establish alone |
|---|---|---|
| `Example` | Exact registered examples passed | General or universal behavior |
| `SampledProperty` | A finite sampling campaign under an explicit intent and plan | Exhaustive or universal validity |
| `ExhaustiveFinite` | All members of a declared finite domain were checked | Behavior outside that domain |
| `BoundedModelCheck` | A proposition under explicit model-checking bounds and assumptions | An unbounded theorem |
| `StaticConsistency` | A registered analyzer accepted its exact inventory/configuration | Functional correctness |
| `MutationWitness` | A registered test distinguishes one registered mutant | General mutation adequacy or correctness |
| `UniversalSourceProof` | A theorem about the identified formal source subject | Shipping-byte correspondence |
| `SourceCorrespondence` | A registered relation between source representations | Artifact correspondence unless separately composed |
| `ArtifactCorrespondence` | A theorem/claim is joined to an exact artifact | Correct deployment or unstated external behavior |
| `ReproducibleArtifact` | Independent builds reproduce registered bytes | Behavioral correctness of those bytes |
| `TrustedTranscription` | A typed external round trip under an explicit TCB | Proof or refinement |
| `HumanReview` | A named reviewer assessed a bounded scope | Automatic strengthening of other evidence |

The algebra is *closed* in two senses. Decoding rejects unknown constructors,
and each derivation rule has an exact input signature and permitted conclusion
shape. Opaque backend facts may be retained for audit and invalidation, but they
cannot add a constructor, graph edge, status role, or policy rule.

## 5.4 Sampling as intent, plan, facts, and consumers

EXP-0006--0008 refine sampled evidence into four layers:

1. `SamplingIntent`: common assurance meaning -- generator closure, target
   inventory, seed, requested successful-case budget, persistence posture, and
   empirical ceiling.
2. `BackendSamplingPlan`: a closed backend-specific variant retaining such
   controls as Hypothesis phases/database, fast-check random type/examples, or
   proptest RNG algorithm/rejection/shrink limits.
3. `SamplingObservation`: facts such as attempted, completed, skipped, and
   shrinks, each carrying `Observed`, `Derived(rule, dependencies)`, or
   `Unavailable(reason)` authority.
4. `AdmissionRule`: an explicit consumer naming only the facts required for a
   conclusion.

The separation prevents two opposite errors. Backend execution detail is not
discarded merely because it is not common, and a common rule need not branch on
framework names. Availability is not encoded as a nullable integer: unavailable
is a typed state, while zero remains an observed or derived value.

## 5.5 Canonical encoding and exact joins

Canonical representation is part of semantics because identities, references,
and caches depend on bytes. The draft requires strict UTF-8 JSON, recursively
sorted object keys, no duplicate keys, explicit required-nullable fields,
canonical ordering and duplicate rejection for sets, float rejection, normalized
relative paths, domain-separated hashes, and byte-identical round trips. Unknown
required schemas and enum values fail closed.

Artifact equality is the tuple

$$
  (\text{logical name},\ \text{SHA-256},\ \text{byte size}),
$$

not a digest or label alone. Under Specification 0001's artifact-bound route,
the verifier checks the theorem statement encoding and digest, exact outer
binding form and literal claim/artifact arguments, the artifact-correspondence
record, and equality with exactly one provenance input. Cache validation likewise
joins the exact typed pre-execution dependencies, configuration, tool and adapter
identities, closures, and prior receipt where applicable. Policy validation joins
the selected policy, required facets, cited evidence, assumptions, and blockers.

These joins are load-bearing because self-consistent rehashing is not enough.
An attacker can alter a target, artifact, assumption, or policy and recompute
local hashes; the independent checker must still reject the changed relation.
EXP-0005's adversarial cases include subject, artifact, family, cache, policy,
closure, TCB, and status substitutions precisely for this reason.

## 5.6 Derivation traces

The EXP-0009 candidate models a derivation program as canonical facts, an acyclic
topological list of steps, and one declared conclusion. Facts carry identities,
authority, propositions, and sources. Rules include evidence validation, sampled
and bounded testing, theorem proof, mutation testing, transcription linkage,
artifact binding, assumption derivation, and policy admission. A trace identity
is a domain-separated hash of canonical program bytes.

The checker validates rather than trusts the trace: it reconstructs rule outputs,
checks exact references and authorities, rejects cycles and duplicate identities,
and requires the declared root to equal the actual conclusion. Thus the trace is
an explanation and portable check object, not an adapter-authored certificate of
its own correctness.

# 6. Experimental Method

## 6.1 Preregistration and falsifiers

Each experiment commits questions, pass criteria, falsifiers, corpus scope, and
procedure before execution. Journals are append-only; corrections are later
entries. Machine-readable results are immutable files. The experiment index in
`docs/experiments/README.md` distinguishes `planned`, `running`, `concluded`, and
`abandoned`. Some README headers preserve preregistration-era state, so this
paper uses the append-only journal, immutable result, and current index to identify
execution status rather than rewriting the registration after observing results.

This method limits post-hoc success criteria. It does not eliminate researcher
degrees of freedom: the same project designed the hypotheses, prototypes, and
corpora. Section 9 treats that as a validity threat.

## 6.2 Positive, adversarial, and holdout corpora

Positive cases test representability and expected derivation. Adversarial cases
modify one semantic relationship or encoding and preregister the rejection class.
Attacks include omission, duplicate identity, alias or substitution, changed
assumption, subject/artifact mismatch, inventory skew, cache incompleteness,
unknown rules, cycles, noncanonical encoding, stronger reported roots, and legacy
schema reinterpretation. This follows differential-testing practice
[@mckeeman1998differential] but compares semantic decoders and derivations rather
than compiler output alone.

EXP-0007 is a third-ecosystem holdout. The contract first demonstrated on
Hypothesis and fast-check was frozen before testing proptest 1.11.0. The study
stopped once preregistered falsifiers for its questions had fired instead of
expanding the common contract to force a pass.

EXP-0009 moves beyond hand-selected cases. Six route templates drive a
deterministic generator (`proofbound-exp-0009-generator/1`, seed 9009). It emits
500 valid programs and 500 adversarial programs, each with one mutation. The
sixteen attack classes occur 31 or 32 times each, which is the exact partition
of 500 cases.

\clearpage\thispagestyle{fancy}\vspace*{1.5em}

## 6.3 Independent implementations

The Rust prototype is the repository's `proofbound-ir-prototype` crate. The
independent `assurance_ir_checker.py` lives under `python/proofbound/`; it has its
own decoder and rule tables and does not import producer types or generated
bindings. Independence is architectural, not statistical: two implementations
can share a mistaken specification or design premise. Agreement therefore detects
divergences and ambiguous encodings in the registered domain but is not proof of
correctness.

## 6.4 Evidence snapshot and artifact ledger

All numerical and technical claims in this paper were checked against the
repository snapshot below. Uncommitted working-tree changes are excluded.

```text
e54f428601f53e065262f74b97bba3d7e2b34150
```

Table 3 gives the exact ledger IDs and repository-relative paths
for the principal result artifacts. Each experiment's `ARTIFACTS.md` records the
full 64-digit raw SHA-256 identity.

| Ledger ID | Exact checked-in result path |
|---|---|
| `EXP-0005-A010` | `docs/experiments/0005-assurance-ir-extraction/results/2026-09-02-adversarial-evidence-algebra.json` |
| `EXP-0005-A023` | `docs/experiments/0005-assurance-ir-extraction/results/2026-09-02-q1-completion-capture-audit.json` |
| `EXP-0005-A026` | `docs/experiments/0005-assurance-ir-extraction/results/2026-09-02-portable-family-projection.json` |
| `EXP-0006-X003` | `docs/experiments/0006-explicit-sampling-contract/results/2026-09-02-adapter-owned-driver.json` |
| `EXP-0007-X001` | `docs/experiments/0007-rust-sampling-holdout/results/2026-09-02-proptest-holdout.json` |
| `EXP-0008-X001` | `docs/experiments/0008-layered-sampling-model/results/2026-09-02-layered-sampling-model.json` |
| `EXP-0009-X001` | `docs/experiments/0009-generated-evidence-algebra/results/2026-09-03-generated-evidence-algebra.json` |

## 6.5 Interpretation discipline

Four levels of statement are used below.

- **Implemented:** present in the production verifier or a named research
  prototype at the pinned commit.
- **Bounded experimental evidence:** an observed result over the exact registered
  corpus and implementation.
- **Hypothesis:** a falsifiable programme claim not yet established.
- **Proposal:** a future design or roadmap step without current empirical support.

Passing tests validate the implementation against cases; they are never reported
as proofs. A bounded model-check result is always reported with its bounds and
never as an unbounded theorem. Likewise, independent implementation agreement is
not independence of underlying assumptions.

# 7. Results

## 7.1 Experiment 0005: a plausible kernel, incomplete losslessness

EXP-0005 began with 20 positive projection cases spanning Python, TypeScript,
Rust, Kani, Lean, mutation, distribution, transcription, refinement semantics,
and proof-free release/compiler cases. Independent Rust and Python implementations
agreed on all 20 positives, rejected all 20 registered adversarial cases with the
expected codes, and agreed on 15 canonical domain-hash vectors (three JSON values
across five domains). There were zero producer/checker disagreements and zero
concrete backend-name hits in the generic kernel over that bounded corpus
[@proofbound-exp0005]. This supports RQ2 and the backend-neutral portion of RQ1;
it does not establish semantic sufficiency.

The losslessness audit is the controlling negative result. Revision 1 found only
one of 16 rows forward-complete and none reverse-complete. After reverse projection
and representation hardening, revision 3 reached 12 complete rows, but full
Python, TypeScript, and Rust release captures reopened typed portable-family
coverage. The current checked-in revision 4 records 11 of 16 rows
forward-and-reverse complete and five partial:

- publication decision and complete blocking derivation (`Q1-FIELD-006`);
- registration-to-observation artifact identities (`Q1-FIELD-009`);
- complete typed portable evidence-family details (`Q1-FIELD-012`);
- transitive execution/cache dependencies and retained reuse eligibility
  (`Q1-FIELD-014`); and
- complete admission explanation and derivation trace (`Q1-FIELD-016`).

Consequently Q1 is failed at the current decision point, Assurance IR `/1` is
not frozen, and the Go holdout has not begun. The ordering matters: successful
adversarial parity on a partial representation does not make the representation
lossless.

A later closed portable-family projection covered all 45 captured records with
identical Rust/Python output. Its constructor counts were: 12 examples, seven
mutation witnesses, seven universal source proofs, six human reviews, three
sampled properties, two artifact correspondences, two independent observations,
two reproducible artifacts, two static-consistency records, one bounded model
check, and one trusted transcription. Of the three property records, only one
had explicit sampling semantics; the TypeScript and Rust records remained
`LegacyBackendSampling`. A self-consistently rehashed attempt to upgrade legacy
sampling was rejected.

**Finding.** Evidence kinds cannot safely collapse into generic success. Typed
family substitutions and stronger status assertions were rejected in the corpus,
while complete-capture analysis found semantics that a generic `passed` envelope
did not retain. This is bounded evidence for a closed sum, not proof that the
listed constructors are complete.

## 7.2 Experiment 0006: sampling needs an owned observation boundary

EXP-0006 tested Hypothesis 6.112.0 and fast-check 4.3.0. Ordinary runner output
failed Q1 and Q2; Vitest setup instrumentation failed closed. An adapter-owned
generator/predicate driver then controlled seed, budget, persistence and shrinking
policy, framework execution, counters, and exclusive report creation.

Both positive runs completed exactly 100 cases. Hypothesis used seed 4025493768;
fast-check used seed 424242. Both observations recorded 100 attempted, 100
completed, zero skipped, and zero shrinks. Deliberately false properties produced
typed counterexamples and exited 1: the Hypothesis run made two predicate
invocations and the fast-check run one, with fast-check recording one shrink.
Rust and Python validators rejected all ten preregistered attacks with their exact
classes and introduced no framework-name branch in common validation
[@proofbound-exp0006].

**Finding.** Tool name and seed are insufficient. A sampling contract also needs
generator closure, target inventory, successful-case budget, replay/persistence
and shrinking policies, effective execution controls, actual observations, and a
trusted boundary that can author them. The result passes only at the research
driver boundary; production integration would additionally need outer command,
environment, driver, runtime, and framework provenance.

## 7.3 Experiment 0007: proptest falsifies the flat contract

EXP-0007 froze the EXP-0006 contract and evaluated proptest 1.11.0. With seed
424242, `chacha` RNG, disabled persistence, 100 successful cases, shrink limit
10,000, and local/global rejection limits of 1,000, the positive run made 100
predicate invocations. A counterexample run made 23 and minimized to the recorded
all-zero/false value. Changing only the RNG algorithm to `xorshift` kept the
framework version and seed fixed but produced a distinct execution with 25
counterexample predicate invocations. The EXP-0006 contract identity would not
have changed because RNG algorithm was absent [@proofbound-exp0007].

The stable typed proptest API exposed cases, persistence, rejection limits,
shrink limit, RNG algorithm and seed, plus pass/failure and the minimal failing
value. It did not expose authoritative successful-case, local/global rejection,
or accepted-shrink counters in the required form. The study rejected parsing
human `Display` output, accessing private fields, and treating every predicate
invocation as a fresh attempt. After attack `EXP-0007-A002` triggered the
preregistered falsifiers, the remaining eleven attacks were not executed because
they could not restore the unchanged contract's generality.

**Finding.** A common semantic intention does not imply one identical execution
record across frameworks. Backend-specific controls must remain typed, and facts
must state which observations a backend can authoritatively provide.

## 7.4 Experiment 0008: a layered sampling model

EXP-0008 projected frozen Hypothesis, fast-check, and proptest records into the
intent/plan/authority model. The three corpus files were 2,203, 2,199, and 2,444
bytes respectively for Hypothesis, fast-check, and proptest, with exact hashes
recorded in the result. The common intent retained ceiling, generator, persistence,
seed, successful budget, and targets. Closed backend plans retained the divergent
execution controls. Common validation and admission contained zero framework-name
branches.

Hypothesis and fast-check reported attempted, completed, skipped, and shrink
facts as observed. For proptest, attempted, skipped, and shrink facts were
unavailable; completion was derived from the runner-success contract, intent
budget, and typed pass result. The admission rule consumed only `completed` and
set the ceiling to `empirical-sample`.

Rust and Python agreed on all twelve registered attacks. Notably,
`EXP-0008-A007` made completed budget unavailable and was rejected as
`sampling-admission-blocked`; `EXP-0008-A009` removed unused shrink telemetry and
returned `no-admission-consequence`. Legacy Rust and EXP-0006 records were
rejected as layered schema rather than reinterpreted [@proofbound-exp0008].

**Finding.** Evidence facts need explicit authority, availability, and consumers.
Unavailable but unused telemetry should not create an admission alert. This is an
implemented research rule with bounded differential evidence, not yet a measured
reduction in human notification fatigue.

## 7.5 Experiment 0009: backend-independent closed traces

EXP-0009 used six templates: sampled property, bounded check, theorem, mutation
witness, trusted transcription, and artifact binding. The deterministic generator
created 500 valid and 500 single-mutation adversarial programs under seed 9009.
The corpus covered eleven rules and all sixteen attack classes; attacks occurred
31 or 32 times each. Independent Rust and Python implementations accepted every
valid program with identical conclusions and trace identities and agreed on the
expected rejection or no-consequence result for every adversarial program. The
reported disagreement count and backend-named common-rule count were both zero
[@proofbound-exp0009].

The attacks exercised more than evidence-family substitution. They removed or
replaced exact dependencies, substituted an artifact binding, removed an open
assumption, introduced a cycle, duplicated an identity, used an unknown
backend-named rule, omitted the source of a derived fact, changed the declared
root, introduced noncanonical encoding, attempted to strengthen transcription,
and reinterpreted an older schema. `EXP-0009-A011` made a consumed fact
unavailable and blocked its exact derivation; `EXP-0009-A012` removed unused
duration telemetry and preserved the conclusion without an alert.

**Finding.** Closed derivation traces can remain backend-independent for this
registered slice. Exact references, canonical order, authority checks, and root
validation made the conclusion reproducible across the two implementations. The
finite corpus does not prove the algebra correct, complete, or equivalent to all
production routes.

## 7.6 Cross-experiment synthesis

| Finding | Strongest checked-in support | Epistemic status |
|---|---|---|
| Evidence families must not flatten to `passed` | EXP-0005 family/status attacks; EXP-0009 coercion attacks | Bounded experimental evidence |
| Sampling needs more than tool name and seed | EXP-0006 observation failures; EXP-0007 RNG falsifier | Direct negative and bounded positive evidence |
| Facts need authority, availability, and explicit consumers | EXP-0008 twelve attacks; EXP-0009 A010--A012 | Bounded experimental evidence |
| Closed traces can be backend-independent | EXP-0009 six routes, eleven rules, 500/500 programs | Bounded experimental evidence |
| Unused unavailable telemetry should not alert | EXP-0008 A009; EXP-0009 A012 | Implemented research semantics, not a user outcome |
| Legacy records must remain visibly weaker | EXP-0005 1 explicit/2 legacy sampling records; EXP-0006 Q4; EXP-0008 A011--A012 | Bounded migration evidence |
| Exact joins are essential | EXP-0005 subject/artifact/cache/policy attacks; Specification 0001 verifier contract | Implemented production checks plus bounded attacks |

# 8. Discussion

## 8.1 Why the result is a language problem

One could encode the candidate records in TOML or JSON and stop. That would be
useful, and the roadmap explicitly allows the programme to end as a framework or
typed assurance DSL. The language hypothesis arises because authoring constraints,
module composition, effects, assumptions, invalidation, and diagnostics may be
safer when they are static properties rather than scattered runtime conventions.
For example, a frontend could reject a sampled property where policy demands a
universal source proof, or a supposedly hermetic build that requests network
authority, before running any backend.

Yet syntax is deliberately deferred. The difficult commitment is the semantic
kernel and its migration boundary. Designing a polished language before finishing
lossless IR extraction would freeze current omissions into source compatibility.
The project's current decision is therefore to continue Gate 1 only.

## 8.2 The Tower of Babel risk

Cross-ecosystem assurance naturally accumulates dialects: pytest nodes, Vitest
selectors, Hypothesis phases, fast-check random types, proptest RNG algorithms,
Kani harness metadata, Lean theorem environments, Aeneas translation reports,
wheel rules, npm package rules, and tool-specific availability conditions. Putting
each directly into the kernel yields a union of backend schemas rather than a
language-neutral semantics. H1's explicit falsifier is such proliferation.

The proposed containment strategy has two parts.

**Small semantic kernel.** Common meaning is limited to typed claims, subjects,
identities, evidence constructors, authorities, derivation rules, and policy
decisions. The kernel rejects unknown required semantics and never branches on
concrete backend names. EXP-0005, EXP-0008, and EXP-0009 report zero such branches
in their tested common validators.

**Typed backend boundaries.** Diversity is retained in closed backend plan/detail
variants and provenance. A backend adapter may know how Hypothesis represents
phases or how Kani enumerates harnesses; it cannot decide that the observation is
a proof. A new backend either maps losslessly to an existing evidence constructor
with a typed plan and capability description, or motivates an explicit versioned
semantic change. Opaque fields may affect audit and invalidation but cannot acquire
derivation authority.

This is containment, not elimination. The number of backend schemas can still
grow, adapters can be wrong, and duplicated conversion logic can hide mistakes.
The architecture only keeps that growth outside the smallest status-checking
boundary and makes its consequences testable.

## 8.3 Exact joins are the semantics

It may appear pedantic to join logical name, digest, and size rather than digest
alone, or to preserve plan identity separately from intent. The experiments show
why these details are not metadata. A theorem, artifact, source closure, cache
entry, and policy can each be valid independently while their composition is
invalid. Assurance depends on the relation: *this* theorem, about *this* claim,
corresponds to *this* exact input artifact under *this* policy and dependency
closure.

Canonical encoding makes local identity reproducible; exact joins make global
meaning reproducible. Both are needed. A self-consistent local rehash after a
substitution is an attack, not validation.

## 8.4 Practical adoption: bridge before destination

The practical path starts with existing systems. Proofbound can register claims
over Python, TypeScript, and Rust; observe pytest, Hypothesis, Vitest, fast-check,
static analyzers, and mutation witnesses; integrate Kani bounded checks; retain
Aeneas/Charon translation and refinement boundaries; ingest Lean theorem evidence;
and bind reproducible distributions and artifacts. These integrations are
heterogeneous by design. They create the empirical corpus from which stable
language semantics can be extracted.

Mixed-language systems should remain a permanent state. A future DSL can author
assurance programmes for foreign code. A future native component can compile into
the same IR and coexist with Python or TypeScript callers. The native route is
justified only if it measurably strengthens correspondence, static effect control,
usability, or notification quality without inflating the trusted base or proof
burden. Until then, the bridge is the product and the research instrument.

## 8.5 Publication, uncertainty, and human judgment

The proposed model does not abolish uncertainty. Stakeholder intent, hardware,
external services, operators, credentials, and organizational processes remain
outside many formal models. The language vision makes assumptions, exclusions,
owners, expiry, and consequences first-class so they can participate in
invalidation and publication decisions.

Human review is similarly typed as evidence about a declared scope. It may
acknowledge an exception or evaluate an assumption; it does not upgrade sampled
evidence into proof. A useful notification should name the affected claim,
dependency path, failed rule, and requested decision. Whether this presentation
actually improves decision quality is open research, not a conclusion from the
current corpora.

# 9. Threats to Validity and Limitations

## 9.1 Construct validity

The experiments operationalize semantic sufficiency through registered fields,
reverse projections, attacks, and status parity. The field inventory may omit a
real assurance concept, and the chosen statuses may not capture how organizations
reason about risk. The programme's refusal to produce a numeric score prevents
one class of false precision but does not demonstrate that its facet structure is
complete.

Notification consequences are tested as rule behavior, not as human outcomes.
No developer, security engineer, release owner, or auditor study has yet measured
missed critical consequences, false escalation, investigation time, or dismissal
rates. Claims of reduced notification fatigue would therefore be premature.

## 9.2 Internal validity

The project authors designed the models, implementations, generators, and most
corpora. Independent Rust/Python implementations reduce common-code failure but
not common-specification bias. Many EXP-0005 fixtures are projections of existing
records without re-executing the original evidence backends. The generated
EXP-0009 corpus is deterministic and broad over registered rules, but every
adversarial program contains exactly one mutation and is derived from six templates.
Multi-fault interactions and unanticipated attacks are underrepresented.

The checked-in worktree includes research prototypes, not a formally verified
checker. Unit tests, differential checks, and adversarial corpora provide bounded
evidence only. They do not prove implementation soundness.

## 9.3 External validity

Sampling studies cover Hypothesis 6.112.0, fast-check 4.3.0, and proptest 1.11.0.
Other versions and property systems may expose different controls or observation
capabilities. The portable corpus contains 45 captured records from three release
verticals; the 500/500 derivation corpus spans six routes, not every production
constructor. The planned Go holdout has not started because EXP-0005's losslessness
gate remains open.

Formal-method integrations are also selective. Lean, Kani, and Aeneas exercise
important theorem, bounded, and refinement boundaries, but do not stand for all
proof assistants, SMT solvers, abstract interpreters, symbolic executors, or
verified compilers. Backend-neutrality is supported only for the tested routes.

## 9.4 Migration and compatibility limits

The draft `proofbound-assurance-ir/1` schema is explicitly non-normative,
partially implemented, and not frozen. No production manifest, receipt, cache,
release, or verifier is authorized to emit or accept it. Legacy property receipts
preserve their current empirical ceiling and identities but lack explicit sampling
meaning. Reclassifying them without new evidence would be a semantic upgrade and
is rejected by the prototypes.

Current open gaps include complete publication traces, execution-time artifact
identity joins, typed portable-family coverage in the central IR, complete
transitive cache dependencies, and admission explanation. The uncommitted
prototype work present in the local checkout is outside this paper's evidence
snapshot and does not change these reported results.

## 9.5 Scope limits

Proofbound does not establish that public claim wording matches stakeholder
intent, that hardware implements a formal machine model, that external services
honor contracts, or that operators deploy the checked artifact and configuration.
It can name these as assumptions or correspondence obligations. It cannot remove
them by language design.

The system also does not turn deterministic reproduction into behavioral
correctness, tool availability into evidence, review into proof, or a successful
model theorem into an artifact claim. These are permanent boundaries rather than
missing features.

# 10. Research Roadmap

The roadmap is dependency-ordered, not a delivery schedule
(`docs/research/proofbound-language/roadmap.md`).

| Gate | Research objective | Exit condition relevant to language work |
|---|---|---|
| 1. Shared semantics | Finish Assurance IR, evidence algebra, invalidation, and independent checking | Smaller than backend-schema union; every status explicit; zero known false retention |
| 2. Authoring and authority | Compare typed DSLs and prototype effects/capabilities | Equivalent frontends emit identical IR; demonstrated authority defects prevented |
| 3. Product value | Study uncertainty and claim-oriented notifications | Lower irrelevant escalation without more missed critical consequences |
| 4. Native feasibility | Build one small deterministic executable subject and artifact story | Independently checkable assurance stronger than comparable existing-language integration |
| 5. Adoption bridge | Test mixed native/foreign systems and final independent kernel | Honest, usable migration with existing-language Proofbound still first-class |

The immediate next experiment is invalidation. It must mutate code, tools,
permissions, missing paths, configuration, assumptions, policies, and external
contracts; predict affected conclusions from typed dependencies; execute fresh
checks; and require zero false retention in the registered corpus. It should also
measure invalidation precision so safety does not degenerate into whole-repository
reruns.

Only after Gate 1 should an assurance DSL be compared with existing typed
configuration approaches such as restricted Pkl or CUE. Equivalent TOML and DSL
programmes must compile to byte-identical canonical IR, and diagnostics should
make real substitution errors unrepresentable before execution. An effect model
then needs to separate static capability claims, operating-system enforcement,
and post-execution observations for `Read`, `Write`, `Execute`, environment,
network, clock, randomness, secret, and human-judgment authority.

The native experiment, if reached, should be deliberately small: a canonical
parser/serializer, policy evaluator, protocol state machine, ledger transition,
or capability-token validator. It must compose with an existing Python or
TypeScript claim, expose its universal proof obligations separately from examples
and sampled properties, and bind the resulting artifact. Failure to outperform a
small component in Verus, Lean, Dafny, or another existing verified language is a
reason to stop, not to widen the implementation.

The roadmap admits three legitimate outcomes: remain an assurance framework if
no compact semantic core survives; ship only a typed assurance DSL if authoring
improves but native execution does not; or specify a native language only after
mixed-language Gate 5 passes. This staged decision rule is the main defense
against premature language design.

# 11. Conclusion

Proofbound's assurance-language programme begins from a narrow claim: software
assurance requires a representation richer than a set of green jobs. Claims,
assumptions, uncertainty, authority, evidence family, artifact correspondence,
derivation, invalidation, policy, and publication are different semantic objects.
Treating them as such can prevent known strengthening and substitution errors.

The checked-in experiments provide bounded support for several design choices.
Evidence families cannot safely collapse into generic success. Sampling requires
common intent, typed backend controls, authority-indexed facts, and explicit
consumers. Unavailable unused telemetry need not generate an admission alert.
Legacy evidence can remain usable only if it remains visibly weaker. Canonical
bytes and exact artifact, provenance, cache, assumption, and policy joins are
necessary to resist self-consistent substitution. Closed derivation traces were
backend-independent across six routes, eleven rules, and 1,000 generated programs
with zero Rust/Python disagreement.

The negative result is equally important. Assurance IR `/1` is not lossless or
frozen: five of sixteen registered rows remain partial, invalidation has not yet
met its gate, and no human notification study or native-language experiment has
run. The generated corpora are tests, not proofs of the algebra. The present
research outcome is therefore continuation of Gate 1, not adoption of a language.

That restraint defines the practical strategy. Proofbound first serves as a
bridge over Python, TypeScript, Rust, Lean, Kani, Aeneas, and related tools. The
bridge supplies useful typed evidence while producing the data needed to decide
whether a native language would remove accidental semantic diversity or merely
add another dialect to it.

# References
