# Experiment 0011: Dual frontend equivalence

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-004
- **Status:** planned; preregistered, not executed
- **Registered:** 2026-09-03
- **Started / concluded:** — / —
- **Subject:** Proofbound `f7fac0cabe5eddc0f4a5e7f211b6d1b43d8c1687`
- **Operator:** Codex (GPT-5)

## Why this experiment

Proofbound's TOML manifests are intentionally explicit, but their strictness is
mostly enforced after parsing and repeated fields obscure the assurance
programme behind adapter-shaped documents. A custom language could make
invalid programmes unrepresentable and factor repetition, or it could merely
replace punctuation while adding another trusted compiler. Pkl offers typed
configuration, abstraction, and validation, but its evaluator can also read
files, environment variables, packages, and networks unless its authority is
restricted.

This experiment compares three authoring frontends over one bounded semantic
subset:

1. the current TOML manifests;
2. a small custom Proofbound research DSL; and
3. Pkl 0.32.1 evaluated under a closed local-module and no-resource policy.

The comparison targets a research-only frontend IR. It does not repair or
freeze Assurance IR `/1`, and byte equality does not imply that dependency
declarations are complete after EXP-LANG-003's falsifier.

## Questions (pre-registered)

1. **Q1 — Semantic equivalence.** Can TOML, the custom DSL, and restricted Pkl
   express the registered Python, TypeScript, and Rust programme slices with
   one meaning? **Pass:** independently implemented Rust and Python compilers
   each produce byte-identical canonical frontend IR, effective programme, and
   derived research receipt for all nine project/frontend pairs; both
   implementations also agree with each other. **Falsifier:** any semantic or
   byte mismatch, accepted frontend-only meaning, or frontend-name branch in
   common validation or receipt derivation.
2. **Q2 — Earlier, typed failure.** Do typed frontends reject invalid assurance
   programmes before evidence execution and locate the source construct?
   **Pass:** all registered substitutions, omissions, duplicates, aliases, and
   join failures are rejected with their exact code before any tool command;
   every source-origin error names a file and nonempty byte span; at least one
   error accepted by TOML syntax is unrepresentable in the custom grammar or
   Pkl type. **Falsifier:** an invalid case reaches execution, is silently
   normalized, lacks a source location, or differs between implementations.
3. **Q3 — Measured abstraction.** Do language abstractions reduce repeated
   assurance declarations without hiding effective meaning? **Pass:** for at
   least two projects, both the custom DSL and Pkl use at least 25% fewer
   source-level semantic assignments than the corresponding TOML corpus under
   the frozen assignment-count algorithm, while rendering the same complete
   effective programme. **Falsifier:** reduction occurs only by omitting
   meaning, fewer than two projects meet the threshold, or a reader must
   evaluate imports mentally because the effective programme is incomplete.
4. **Q4 — Determinism and authority closure.** Can evaluation be deterministic
   and its actual frontend dependency closure be bound? **Pass:** ten clean
   evaluations of every positive frontend produce identical bytes and exact
   dependency identities; Pkl runs with only the registered local module root,
   no resource schemes, no cache, empty inherited environment, and a bounded
   timeout; environment, network/package, path-escape, unregistered-import,
   tool-substitution, clock/random, and dependency-byte attacks all fail
   closed or change the bound frontend identity. **Falsifier:** ambient state
   changes output without identity, an unregistered dependency is consumed,
   or a forbidden authority succeeds.
5. **Q5 — Effective-program and source-map integrity.** Can authors review the
   generated meaning without trusting the frontend evaluator? **Pass:** each
   compiler emits a standalone canonical effective programme accepted by the
   independent checker; every semantic leaf has exactly one valid source span;
   source-map deletion, overlap, file substitution, span substitution, IR-leaf
   substitution, and noncanonical effective bytes are rejected with the
   registered code. **Falsifier:** any leaf is unmapped or multiply mapped, a
   forged mapping is accepted, or validation requires the original frontend
   evaluator.

The experiment measures representation and compiler behavior, not subjective
usability. No participant study is used to claim faster authoring or better
human comprehension.

## Candidate semantic boundary

```text
FrontendProgramme {
  schema: "proofbound-research-frontend-programme/1"
  project: Project
  claims: Set<Claim>
  evidence: Set<EvidenceUnit>
}

EvidenceUnit =
    ExampleTest<Inventory, Operation, Budget>
  | SampledProperty<Inventory, Generator, Seed, Operation, Budget>
  | BoundedCheck<Inventory, Domain, Operation, Budget>
  | MutationWitness<Mutation, Inventory, Operation, Budget>
  | UniversalTheorem<Declaration, StatementIdentity, Operation, Budget>

FrontendCompilation {
  programme: FrontendProgramme
  source_map: TotalMap<SemanticLeaf, SourceSpan>
  dependencies: Set<ArtifactIdentity | ToolIdentity | AuthorityPolicy>
}
```

Claims retain statement, subject, assurance profile, linkage, evidence,
assumptions, premises, obligations, exclusions, source roots, and optional
formal/bounded-domain detail. Evidence retains exact inventory, inputs,
environment, operation, budgets, assumptions, and family-specific parameters.
Sets are strict lexical sets; source order never changes meaning.

The derived research receipt contains the canonical programme identity,
effective-programme identity, source-map identity, frontend dependency
identities, and project ID. It contains no execution or assurance status.

## Registered subjects

- Python inventory service: one claim plus exact pytest example and seeded
  Hypothesis property units;
- TypeScript codec: one claim plus exact Vitest example and bounded fast-check
  property units; and
- Rust allowance kernel: one claim plus Cargo example, Kani bounded check,
  mutation witness, and Lean theorem units.

The exact paths and SHA-256 identities are frozen in `preregistration.json`.
The later corpus commit will add equivalent DSL and Pkl sources without
changing these TOML meanings.

## Registered measurements

- `M-FRONT-001`: canonical programme agreement, exact match count / 9;
- `M-FRONT-002`: independent implementation agreement, exact match count / 9;
- `M-FRONT-003`: rejected attacks by exact code / registered attacks;
- `M-FRONT-004`: source-map leaf coverage and unique coverage;
- `M-FRONT-005`: semantic assignments per project/frontend;
- `M-FRONT-006`: assignment reduction versus TOML;
- `M-FRONT-007`: deterministic repetitions / 10 per positive case; and
- `M-FRONT-008`: bound dependency identities and forbidden-authority outcomes.

A semantic assignment is one explicit AST property-to-value binding before
default or pattern expansion. Collection elements count individually; syntax,
comments, whitespace, delimiters, and generated effective fields do not.
The metric implementation and expected TOML counts are frozen with the corpus
before frontend implementation.

## Registered attacks

The machine preregistration fixes exact codes for sampled-as-theorem,
unbound-theorem, duplicate and partial inventory, unowned assumption,
conflicting policy ceiling, undeclared tool authority, unknown field, stable-ID
alias, noncanonical order, Pkl environment/resource and remote/package access,
path escape, unregistered import, evaluator substitution, dependency-byte
drift, and six source-map/effective-programme integrity attacks.

## Scope

- **In:** the three registered programme slices; TOML, custom DSL, and Pkl
  frontends; research-only Rust and Python compilers/checkers; canonical JSON;
  typed defaults/patterns; formatter; effective programme; source map; closed
  evaluator authority; deterministic local execution; structural authoring
  metrics.
- **Out:** production manifest replacement; editor/LSP implementation;
  participant usability study; arbitrary Pkl packages; remote imports;
  evidence-tool execution; production receipts; fixing EXP-LANG-003's read
  boundary; final Proofbound language syntax.

## Procedure

1. Commit this registration before adding frontend sources or compilers.
2. Freeze the selected TOML projection, assignment metric, equivalent DSL/Pkl
   sources, expected canonical IR, and attack fixtures in a separate corpus
   commit.
3. Implement the custom grammar, formatter, compiler, effective renderer,
   source map, and receipt derivation in Rust.
4. Implement an independent Python compiler and checker without generated
   bindings or shared parsing/validation code.
5. Evaluate Pkl with the registered security policy and bind its exact binary,
   version, source modules, and authority arguments.
6. Run all nine positive pairs ten times, all attacks, the metric comparison,
   and independent effective-program validation.
7. Conclude Q1–Q5 separately. Do not adopt a production frontend here.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0011-F001 | Reserved for execution. | — | pending |

## Outcome

Q1–Q5 are unanswered. No frontend corpus or implementation exists yet.
