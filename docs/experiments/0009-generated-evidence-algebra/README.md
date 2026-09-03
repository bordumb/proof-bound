# Experiment 0009: Generated evidence algebra

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Status:** planned
- **Registered:** 2026-09-03
- **Started / concluded:** — / —
- **Subject:** Proofbound derivation sources at
  `5a88f4e8102e125171c38c1222b440abf21ce8d0`
- **Operator:** Codex (GPT-5)

## Why this experiment

Proofbound already derives status independently, but the derivation is not yet
a first-class, portable proof object. EXP-0008 showed that typed facts,
backend-neutral rules, and consequence-indexed admission can distinguish a
load-bearing unknown from harmless missing telemetry. This experiment tests
whether that structure generalizes across representative evidence families.

The candidate algebra keeps four things separate:

```text
Fact                  registered, observed, reviewed, derived, or unavailable
DerivationStep        one closed rule applied to exact fact/step references
Judgment              evidence validity, status facet, or policy decision
DerivationTrace       canonical acyclic graph ending at one declared conclusion
```

Evidence facts never contain a reported claim status. A rule may derive only
the judgment allowed by its constructor. Policy may select admissible
judgments; it may not reinterpret sampled or bounded evidence as a theorem.

## Questions (pre-registered)

1. **Q1 — Representative completeness.** Can sampled property, bounded check,
   theorem, mutation witness, trusted transcription, and artifact binding each
   produce a complete derivation trace ending in the registered formal,
   linkage, assumption, and policy judgments? **Pass:** all six positive
   templates and at least 500 deterministically generated valid programs are
   accepted by Rust and Python with identical conclusions and trace identity.
   **Falsifier:** a selected route needs an opaque status field or a
   backend-named common rule.
2. **Q2 — Forbidden coercions.** Can a closed rule signature reject stronger
   reinterpretations? **Pass:** sampled-to-proved, bounded-to-universal,
   theorem-to-artifact-bound without correspondence, and transcription-to-
   refined or proved substitutions all fail with the registered rule-input or
   conclusion error. **Falsifier:** a self-consistent rehash admits one.
3. **Q3 — Trace integrity.** Can exact references and canonical topological
   order make every accepted conclusion reproducible? **Pass:** dependency
   removal/substitution, duplicate identity, cycle, unknown rule, derived-fact
   omission, noncanonical encoding, and reported-root substitution fail
   independently. **Falsifier:** either validator accepts an ambiguous or
   cyclic trace, or the validators disagree.
4. **Q4 — Generated differential agreement.** Do independent implementations
   agree beyond hand-selected examples? **Pass:** a registered deterministic
   generator produces at least 500 valid and 500 single-mutation adversarial
   programs spanning every rule, and Rust/Python agree on acceptance,
   conclusion, identity, or exact rejection code. **Falsifier:** any unexplained
   disagreement or unexercised rule remains.
5. **Q5 — Consequence-indexed uncertainty.** Does an unavailable fact notify
   only through a consuming derivation or admission rule? **Pass:** removing a
   required completion or binding fact blocks the exact dependent conclusion
   and names its rule; removing unused telemetry preserves the conclusion and
   produces no alert. **Falsifier:** both changes receive the same generic
   warning, or a load-bearing unavailable fact is silently ignored.

The finite corpus cannot prove the algebra correct for all possible programs.
It can falsify the candidate and establish agreement for the registered domain.

## Candidate model under test

```text
DerivationProgram {
  schema: "proofbound-derivation-program/1"
  facts: Set<Fact>
  steps: TopologicalList<DerivationStep>
  conclusion: StepId
}

Fact {
  id: FactId
  authority: Registered | Observed | Reviewed | Derived | Unavailable
  proposition: EvidencePassed | BindingMatches | AssumptionOpen |
               PolicyRegistered | Telemetry
}

DerivationStep {
  id: StepId
  rule: EvidenceValid | EmpiricalTested | BoundedTested | TheoremProved |
        MutationTested | TranscriptionLinked | ArtifactBound |
        AssumptionFacet | PolicyAdmitted
  inputs: Set<FactId | StepId>
  conclusion: Judgment
}

Judgment = EvidenceValidity | FormalFacet | LinkageFacet |
           AssumptionFacet | PolicyDecision
```

Every rule has a closed input signature and one permitted conclusion shape.
`PolicyAdmitted` consumes a registered policy plus the exact judgments named
by that policy. An unavailable fact has identity and reason but cannot satisfy
a positive rule input.

## Procedure

1. Freeze the production status corpus, Assurance IR draft, EXP-0008 result,
   and current derivation implementation.
2. Define the research-only typed program, fact, rule, judgment, and trace
   identity in Rust.
3. Create six positive templates and a deterministic bounded generator.
4. Implement an independent Python decoder and derivation checker without
   generated bindings or shared derivation code.
5. Execute every registered attack and a 500/500 generated differential run.
6. Decide Q1–Q5 separately. Do not adopt a production schema here.

## Scope

- **In:** six representative evidence routes; current public status facets;
  assumption and policy admission; exact trace dependencies; unavailable-fact
  consequences; canonical JSON; deterministic generated cases.
- **Out:** complete production-rule parity; backend execution; probability or
  confidence; policy authoring syntax; invalidation performance; production
  wire migration; formal proof of the checker.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0009-F001 | Reserved for execution. | — | pending |

## Outcome

Q1–Q5 are unanswered. No experiment execution has started.
