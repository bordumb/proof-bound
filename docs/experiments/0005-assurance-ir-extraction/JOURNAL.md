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

## 2026-09-01 — Positive projection corpus revision 1

Froze 20 positive projection cases against exact Git blob bytes at baseline
`295ad63e67bd30cc48eb8c9ee43c612de2c367c6`. The corpus covers Python and
TypeScript example, property, static, mutation, and distribution registrations;
Kani, Lean, and Rust registrations; six backend-free semantic status cases;
and the canonical portable release fixture.

The inactive Aeneas refinement example remains explicitly non-executed. Its
translation registration is pinned as supporting input, while source-refinement
semantics come from the positive conformance case. This avoids turning an
aspirational demo into fabricated observation evidence. No converter or
projection comparison has run, so Q1, Q3, and Q5 remain unanswered.

## 2026-09-01 — Draft Assurance IR `/1`

Drafted a non-normative Assurance IR from inventory revision 2 and the frozen
positive corpus. The model separates authority, uses a closed evidence sum,
keeps status as derived output, moves backend dependencies outside common
provenance, names an explicit cache-dependency projection, and preserves
distinct empirical, bounded, formal, correspondence, transcription, and
reproducibility meanings.

The draft does not hide the current sampled-property asymmetry: registered
Hypothesis facts map to explicit sampling, while the current TypeScript route
maps to a visible legacy backend-sampling state pending OQ-001. It also records
the inactive Aeneas route honestly. The schema name is reserved only inside the
research draft; no implementation may emit it yet. Q1–Q5 remain unanswered.

## 2026-09-01 — Adversarial and canonical preregistration

Before implementing either prototype, froze 20 independent adversarial
mutations and their expected rejection phases/codes. Also froze the canonical
JSON contract, five research-only domain strings, and 15 expected domain-hash
vectors. This prevents either implementation from choosing encodings or
negative cases after observing the other's behavior.

The registered attacks cover every minimum Q3 category plus cache dependency,
required-unknown, claim-attribution, evidence-strength, and reported-linkage
attacks. They remain unexecuted.

## 2026-09-01 — Initial projection parity run

At implementation commit `757f42096b896d3bdb41b896a46bfad3dcdc2ca4`,
ran a typed Rust producer and separately written Python checker over all 20
frozen positive cases. The producer verifies source identities and projects
registration, semantic-status, and release cases. The Python checker imports no
producer types, reconstructs the same projection directly from frozen source,
and independently checks canonical bytes and domain identities.

The implementations agreed on all 20 cases and all 15 preregistered canonical
domain vectors. The canonical projection identity was
`sha256:357cc0d521f46e9f360d06c378d32e0c2b1acd1de72ab38b5d8686e6fcfdd558`.
This is deliberately a boundary prototype: it does not yet materialize the full
AssuranceProgram, rederive every status from the evidence algebra, or execute
the 20 preregistered adversarial transformations. No EXP-0005 question is
therefore marked passed.

## 2026-09-02 — Adversarial corpus correction before execution

While materializing the adversarial harness, IR-ADV-003 was found to reverse a
singleton run list. That operation is an identity transformation and could not
test the registered ordering invariant. No adversarial case had been executed.

The adversarial corpus therefore advances to revision 2 before execution.
IR-ADV-003 now changes the sole source-derived run's command index from zero to
one and retains `IR-PROVENANCE-RUN-ORDER` as its expected rejection. The other
19 cases are unchanged. Results must bind revision 2 and its new digest; the
initial positive-only result remains bound to revision 1.

## 2026-09-02 — Adversarial evidence-algebra run

At implementation commit `f577a55dc01e70dfcd595a45b71855ae052db58b`,
expanded every positive projection into a canonical per-case Assurance IR
document. Independently implemented Rust and Python validators rederive the
registered family/detail relationship, subject and artifact joins,
assumptions, claim attribution, cache dependency and reuse binding, run order,
and status ceilings without executing an evidence backend.

Both validators rejected all 20 adversarial revision-2 cases with the exact
registered codes. They also retained agreement on all 20 positive cases and 15
canonical vectors. A literal backend-schema branch discovered during the first
local run was removed before the implementation commit: typed sampled-property
detail now declares its required fact schemas, and the generic validator only
checks declaration membership. Neither generic validator contains a concrete
backend name.

This is bounded evidence for Q2, Q3, and Q4. Q1 remains unanswered because the
prototype does not yet preserve every registered projection field or implement
reverse conversion. Q5 remains unanswered because complete versioned migration
has not been exercised. The machine-readable result records those limits and
must not be cited as completion of Experiment 0005.

## 2026-09-02 — Q1 losslessness gap audit

Before extending the successful adversarial prototype, froze a 16-row matrix
against the exact semantic projection registered by Q1. Only claim identity is
forward-complete. Status facets are present but mix exact derivation with
aggregate registration ceilings. Every other row is partial, minimal,
synthetic, a placeholder, or missing, and no row has a reverse projection.

In particular, the current case document must not be described as a lossless
AssuranceProgram. It does not retain actual claim subjects and meaning,
complete inventories and artifact tuples, closures, full provenance, actual
cache dependencies, TCB/tool identities, or complete policy explanation. The
matrix fixes the acceptance boundary before implementation: Q1 passes only
when all applicable source values survive a source-to-IR-to-source semantic
round trip, without substituting opaque hashes for required meaning.

## 2026-09-02 — Positive corpus revision 2 for Q1

Expanded each registration case with the exact claim-manifest path and SHA-256
for every attributed claim. Earlier revision-1 results remain immutable and do
not retroactively cite these bytes. The expansion is required because Q1 names
actual subject identity, internal and public meaning, claim policy, assumptions,
obligations, exclusions, and registered inputs; deriving placeholders from a
claim ID cannot satisfy that contract.

No Q1 comparison has run against revision 2. The expected statuses, evidence
registrations, semantic conformance pointers, and release fixture are unchanged.

## 2026-09-02 — Q1 forward-projection progress run

At implementation commit `6f9b89e`, ran corpus revision 2 through the expanded
Rust projection and independent Python reconstruction. Both implementations
agreed on all 20 canonical programmes with projection identity
`sha256:7e44e8f988292bc5895efa9a83a67a228fd8da2e5c033e545925c5a1aea68dd4`.

Registration cases now retain actual claim meaning and the complete evidence
request rather than placeholders or configuration-only hashes. The portable
case now retains the evidence content address, complete execution provenance,
project identity, graph and ledgers, policies, closures, sealed artifacts, and
publication blockers. Both validators reject a missing portable policy and a
project/provenance revision substitution with matching stable codes.

This does not pass Q1. The portable programme does not yet reverse-project to
the receipt's registered semantic value, registration cache dependencies remain
a research placeholder, and graph, policy, assumption, and premise values are
preserved but not yet independently interpreted as typed kernel records. The
machine-readable result records these limits so forward completeness cannot be
mistaken for losslessness.

## 2026-09-02 — Q1 adversarial corpus preregistration

Before extending programme-level semantic validation, froze twelve additional
portable-projection attacks in `corpus/q1-adversarial-cases.json`. They cover
schema and presentation omission, status and policy divergence, unknown typed
fields, self-consistent graph mutations with refreshed identities, closure
omission, duplicate statuses, false publication blockers, and broken
assumption/premise joins.

These cases have not been executed. The implementation-derived omission and
identity tests run earlier remain useful regressions but are not retrospectively
called preregistered. The new corpus fixes exact rejection codes before the
kernel changes needed to satisfy them.

## 2026-09-02 — Q1 losslessness decision

At implementation commit `fb12290`, executed the twelve previously frozen Q1
attacks without changing their bytes. Rust and Python independently rejected
all twelve with their exact registered codes. The same implementations
projected all twenty positive cases to canonical programmes with projection
SHA-256 `3107fafe494d200f808951ed608f913692aff056d06ca53882dcd85968eb8fc4`.
The portable fixture passed an explicit receipt-to-IR-to-receipt semantic
comparison, including claim presentation, evidence and provenance, graph,
policy, closure, ledger, status, and publication joins.

The revision-2 losslessness audit nevertheless fails Q1. Nine of sixteen rows
are forward-and-reverse complete; seven remain partial. Known gaps are a
canonical subject-closure identity for registration projections, full
admission traces, closed typed artifact-role and evidence-family records,
complete transitive cache-dependency evidence, and typed backend/TCB component
semantics. These are representation gaps, not attack-test failures.

Accordingly, Assurance IR `/1` is not frozen and the Go holdout is not
preregistered. Doing either now would turn known omissions into compatibility
commitments and would make a holdout measure adaptation to an incomplete IR.

## 2026-09-02 — Q1 representation hardening

After the failed Q1 decision, closed three of its seven known representation
gaps without changing the frozen corpus or either preregistered adversarial
suite. Registration claims now carry a domain-separated subject closure over
normalized selectors and exact source bytes. Evidence-family meaning is a
closed typed record whose registered projection must exactly reconstruct the
source family configuration. Known retained backend facts are typed, and the
portable TCB ledger is strictly decoded into typed components, reconstructed
against its sealed bytes, and joined to observed tool and adapter identities.

Rust and Python independently project the same twenty cases, reject all twelve
existing Q1 attacks with their registered codes, and reject additional
post-decision substitution tests for subject selectors, family configuration,
retained facts, artifact roles, and TCB components. Those added tests are
regressions, not retrospectively preregistered attacks.

Matrix revision 3 records twelve of sixteen rows complete and four partial.
The remaining gaps are complete admission derivation traces,
registration-to-observation artifact identity, and transitive execution-cache
dependency completeness. Q1 therefore remains failed, Assurance IR `/1`
remains unfrozen, and a Go holdout is still premature.

## 2026-09-02 — Q1 completion corpus preregistration

Before collecting new observations or implementing admission traces, froze a
completion protocol over full Python, TypeScript, and Rust verticals at subject
commit `f3a5362`. The original corpus intentionally emphasizes registration
and one portable fixture; it cannot by itself prove the remaining
registration-to-observation artifact, transitive cache, and policy-derivation
joins.

The new protocol registers exact capture roles, six derivation-trace attacks,
five artifact attacks, seven cache invalidations, a presentation-only control,
and row-specific decision rules. Missing tools or incomplete identities are
not passes. The experiment will retain bounded semantic records rather than
dependency directories or native binaries. Go remains excluded as the future
holdout and cannot begin until all sixteen Q1 rows pass and Assurance IR `/1`
is frozen.
