# Experiment 0006: Explicit sampled-property contract

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Status:** planned
- **Registered:** 2026-09-02 (commit of this Questions section)
- **Started / concluded:** — / —
- **Subject:** Proofbound completion captures and demos at
  `a1ecfd1c27d3652fde3576eebe3b52cc36d8d68f`; Hypothesis `6.112.0`;
  fast-check `4.3.0`
- **Proofbound:** registration baseline
  `a1ecfd1c27d3652fde3576eebe3b52cc36d8d68f`; pin each implementation run
- **Operator:** Codex (GPT-5)

## Why this experiment

Experiment 0005 found that `property-test` is not one portable semantic
contract. Python Hypothesis evidence retains framework, version, and seed, but
the TypeScript fast-check and Rust property-labelled receipts retain only
artifact/configuration identities and generic test execution. A digest detects
change; it does not tell an independent kernel what sampling occurred.

The gap cannot be closed by parsing TypeScript or Rust application source in
the generic kernel. This experiment tests whether a small explicit sampling
contract can be observed at a backend boundary and normalized without making
the kernel depend on Hypothesis, fast-check, pytest, or Vitest.

Primary framework references establish only the registered capability
baseline:

- [Hypothesis seed API](https://hypothesis.readthedocs.io/en/latest/reference/api.html#hypothesis.seed)
  states that a fixed seed replays the same cases subject to other sources of
  nondeterminism; pytest also accepts `--hypothesis-seed`.
- [Hypothesis settings](https://hypothesis.readthedocs.io/en/latest/tutorial/settings.html)
  define `max_examples` and execution phases.
- [fast-check parameters](https://fast-check.dev/docs/api/interfaces/Parameters/)
  define seed, number of runs, replay path, and random generator selection.
- [fast-check run details](https://fast-check.dev/docs/api/interfaces/RunDetailsSuccess/)
  expose the actual seed, run count, skips, shrinks, and effective run
  configuration.

These are versioned backend facts, not permission to infer a common meaning.

## Questions (pre-registered)

1. **Q1 — Semantic sufficiency.** Can one closed `SamplingContract` preserve
   the assurance-relevant meaning of the selected Hypothesis and fast-check
   properties? **Pass:** for both frameworks, registration and observation
   project to the exact same typed framework identity, framework version,
   replay seed, requested successful-case budget, generator closure identity,
   target inventory, replay policy, and database/persistence policy. An
   independent checker reconstructs the same canonical contract without
   parsing application source or importing either framework. **Falsifier:** a
   required value exists only in prose/source code, two distinct backend
   settings collapse to one contract, or the checker needs a framework-name
   branch.
2. **Q2 — Authoritative observation.** Can the adapter prove that execution
   used the registered contract rather than merely bind bytes that contain it?
   **Pass:** at least one route per framework emits a strict machine result
   containing actual seed, completed/attempted/skipped cases, shrink count,
   and effective replay configuration; the adapter independently matches it
   to registration and exact target inventory. Registration substitution,
   source override, missing report, duplicate field, and same-count target
   substitution all fail before evidence is passed. **Falsifier:** success is
   inferred only from exit status, a source-local override can defeat the
   registered settings, or the report is app-authored without an independently
   checked driver boundary.
3. **Q3 — Adoption boundary.** Is instrumentation of ordinary pytest/Vitest
   properties sufficient, or is an adapter-owned property-driver ABI required?
   **Pass for instrumentation:** existing test functions remain unchanged and
   strict framework output exposes every Q1/Q2 field. **Pass for driver ABI:**
   instrumentation fails closed, while a bounded exported generator/predicate
   interface lets the adapter own execution and emit the complete report.
   Record changed source lines, new manifest fields, commands, and runtime for
   both routes; do not declare the less intrusive route successful if any
   field is inferred. **Falsifier:** neither route can establish the contract,
   or the driver must execute arbitrary app-authored admission logic.
4. **Q4 — Honest migration.** Can existing property receipts remain valid
   without being silently assigned the new meaning? **Pass:** current
   TypeScript and Rust receipts convert only to
   `LegacyBackendSampling(contract_identity)` and retain their existing
   empirical ceiling; new explicit records use a new versioned schema and
   cannot deserialize as legacy or vice versa. Self-consistently rehashed
   legacy-to-explicit, seed, run-budget, generator, and target substitutions
   are rejected by independent implementations. **Falsifier:** compatibility
   requires redefining an existing schema ID or treating a configuration
   digest as the missing sampling semantics.

## Candidate contract under test

This shape is preregistered as a hypothesis, not a specification:

```text
SamplingContract {
  schema: "proofbound-sampling-contract/1"
  framework: ToolIdentity
  seed: Seed { encoding, value }
  successful_cases: U64
  generator: GeneratorIdentity { entrypoint, closure }
  targets: Set<InventoryItem>
  replay: FreshOnly | RegisteredExamplesThenFresh
  persistence: Disabled | ReadOnlyBoundDatabase(ArtifactIdentity)
  shrinking: Enabled | Disabled
}

SamplingObservation {
  schema: "proofbound-sampling-observation/1"
  contract_identity: Sha256
  actual_seed: Seed
  completed_cases: U64
  skipped_cases: U64
  shrink_count: U64
  targets: Set<InventoryItem>
  result: Passed | Counterexample(CounterexampleIdentity)
}
```

`successful_cases` is a requested lower bound, not a universal coverage claim.
The experiment must state how framework phases, fixed examples, skips, health
checks, and shrinking affect the observed counters. It may revise the
candidate only through an append-only journal entry before the affected run.

## Procedure

1. Freeze exact positive properties and framework versions.
2. Capture ordinary-runner behavior without changing either test.
3. Attempt strict instrumentation using only documented public APIs.
4. If any registered field remains unobservable, stop that route and retain
   the failure.
5. Prototype a minimal adapter-owned driver ABI for the same property and
   generator closure.
6. Implement the common contract and validation twice: producer-side Rust and
   an independent Python checker with no backend-name branches.
7. Execute the registered positive, substitution, ambiguity, and migration
   corpus.
8. Record adoption cost and decide Q1–Q4 independently.

## Scope

- **In:** one Hypothesis property, one fast-check property, explicit seed and
  case budget, generator/source closure, replay/persistence policy, structured
  observations, legacy migration, and backend-independent validation.
- **Out:** statistical confidence scores; universal claims; coverage-guided
  fuzzing; distributed corpora; final production schema adoption; production
  adapter changes; native Proofbound syntax; Rust proptest execution; and the
  Go holdout.

## Journal

Execution entries are append-only in [JOURNAL.md](JOURNAL.md).

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0006-F001 | Reserved for execution. | — | pending |

## Outcome

Q1–Q4 are unanswered. No experiment execution has started.
