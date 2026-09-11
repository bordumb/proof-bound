# Experiment 0008: Layered sampling model

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Status:** concluded — Q1–Q5 bounded pass
- **Registered:** 2026-09-02
- **Started / concluded:** 2026-09-02 / 2026-09-02
- **Subject:** EXP-0006 and EXP-0007 results at
  `dcdffb77d01f2eba293d28cd48c5e466f9fea5b8`
- **Operator:** Codex (GPT-5)

## Why this experiment

EXP-0006 passed one exact driver contract for Hypothesis and fast-check.
EXP-0007 then falsified that contract as a complete proptest execution model:
RNG algorithm was missing, and the stable typed API could not authoritatively
expose the same counter set. The wrong response would be a growing bag of
nullable fields or framework-name branches in the assurance kernel.

This experiment tests a three-layer alternative:

```text
SamplingIntent       common assurance meaning and empirical ceiling
BackendSamplingPlan  closed, versioned execution controls owned by a plugin
SamplingObservation  typed facts with explicit authority: observed, derived,
                     or unavailable
```

An unavailable counter is not a warning by itself. It becomes actionable only
when a registered admission or replay rule requires that fact. This connects
the evidence algebra to Proofbound's notification-quality goal: report the
consequence of uncertainty, not every tool-shaped absence.

## Questions (pre-registered)

1. **Q1 — Common intent.** Can all three frameworks share one
   `SamplingIntent` containing generator closure, targets, fixed seed,
   requested successful budget, persistence posture, and empirical ceiling?
   **Pass:** reverse projection reconstructs every common source field and no
   backend execution control is smuggled into intent. **Falsifier:** a common
   field has materially different assurance meaning in one framework.
2. **Q2 — Typed backend plans.** Can framework-specific controls live in a
   closed plan sum while the common validator depends only on plan identity
   and declared capabilities? **Pass:** RNG algorithm, phases, database,
   examples/replay, rejection ceilings, and shrink controls survive exact
   round trip; changing any plan field invalidates execution without changing
   intent. **Falsifier:** common derivation needs a framework-name branch or an
   opaque digest substitutes for a required plan fact.
3. **Q3 — Authority-indexed facts.** Can every observation state each counter
   as `Observed`, `Derived(rule, dependencies)`, or `Unavailable(reason)`?
   **Pass:** no missing fact becomes zero, no derived fact is labelled observed,
   and admission rules request only the facts they need. A proptest pass may
   derive the successful budget from the typed runner-success contract while
   retaining shrink count as unavailable. **Falsifier:** a passing status
   requires inventing a value, parsing prose, or silently weakening a rule.
4. **Q4 — Notification consequence.** Can the model distinguish harmless
   missing telemetry from assurance-blocking uncertainty? **Pass:** removing
   an unused shrink count produces no admission alert; removing a required
   completed-budget fact identifies the affected claim/evidence rule exactly.
   **Falsifier:** both changes produce the same generic warning or a critical
   missing fact is suppressed.
5. **Q5 — Honest migration.** Can legacy, EXP-0006 explicit, and layered
   records remain distinct constructors? **Pass:** self-consistent upgrades,
   plan omission, authority relabelling, and unavailable-to-zero substitutions
   fail independently. **Falsifier:** compatibility redefines an old schema.

## Candidate model under test

```text
SamplingIntent {
  schema: "proofbound-sampling-intent/1"
  seed: Seed
  successful_cases: U64
  generator: GeneratorIdentity
  targets: Set<InventoryItem>
  persistence: Disabled | ReadOnlyBound(ArtifactIdentity)
  ceiling: EmpiricalSample
}

BackendSamplingPlan =
  HypothesisPlan(version, phases, database, shrinking)
| FastCheckPlan(version, random_type, examples, skip_limit, shrinking)
| ProptestPlan(version, rng_algorithm, rejection_limits, shrink_limits)

Fact<T> =
  Observed(value, source)
| Derived(value, rule, dependencies)
| Unavailable(reason)

SamplingObservation {
  intent_identity: Sha256
  plan_identity: Sha256
  attempted: Fact<U64>
  completed: Fact<U64>
  skipped: Fact<U64>
  shrinks: Fact<U64>
  result: Passed | Counterexample(BoundedJson)
}
```

## Procedure

1. Freeze the two EXP-0006 contracts/results and the EXP-0007 holdout result.
2. Define closed typed intent, plan, fact-authority, and observation records in
   the research prototype only.
3. Project Hypothesis, fast-check, and proptest without importing their runtime
   libraries into common validation.
4. Specify admission requirements separately from observation availability.
5. Execute the preregistered substitution and notification-consequence corpus
   in Rust and independent Python.
6. Decide Q1–Q5 separately. Do not adopt production schemas in this experiment.

## Scope

- **In:** the three pinned frameworks; exact common intent; typed backend
  plans; observed/derived/unavailable facts; empirical status ceiling;
  targeted uncertainty consequences; legacy migration.
- **Out:** production wire changes; statistical confidence; arbitrary
  frameworks; final DSL syntax; operating-system sandboxing; universal claims.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0008-F001 | Common sampling intent remains backend-neutral when framework controls live in a closed backend-plan sum and observed, derived, and unavailable facts retain their authority. | `results/2026-09-02-layered-sampling-model.json`; implementation `67e80a7` | Carry the layered model into Assurance IR research without changing production wire formats. |
| EXP-0008-F002 | Missing telemetry is actionable only when a registered derivation consumes it: unavailable completed-budget evidence blocks admission, while unused unavailable shrink telemetry produces no notification. | Registered A009/A010 consequence cases in the immutable result | Use dependency-aware uncertainty consequences in EXP-LANG-006. |

## Outcome

Concluded with bounded passes for Q1–Q5 over the frozen Hypothesis,
fast-check, and proptest corpus. Rust and independent Python implementations
agreed on all positive cases and all twelve registered attacks. The result
supports the layered candidate; it does not adopt a production schema or make
a claim about arbitrary sampling frameworks.
