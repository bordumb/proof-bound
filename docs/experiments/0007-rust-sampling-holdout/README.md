# Experiment 0007: Rust sampled-property holdout

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Status:** planned
- **Registered:** 2026-09-02
- **Started / concluded:** — / —
- **Subject:** allowance kernel and generic Rust property-labelled registration
  at `6a355180aa47bda23408f5de2a20fd10f6234448`
- **Framework under test:** proptest `1.11.0`
- **Operator:** Codex (GPT-5)

## Why this experiment

EXP-0006 found one explicit sampling contract for Hypothesis and fast-check,
but the third captured property record is a Rust test suite with no property
framework or typed sampling facts. This is a holdout, not a retrofit: the
existing receipt stays `LegacyBackendSampling`. A separate adapter-owned
proptest route must either project to the existing contract without loss or
falsify its claimed generality.

The public proptest API exposes a fixed seed, requested successful-case count,
persistence policy, RNG algorithm, rejection ceilings, and shrink ceilings.
`TestRunner::run` returns a typed success or `TestError` with a failing value,
but its successful and rejection counters are private; its `Display` output is
human text. That difference is preregistered as a likely observation gap, not
papered over after execution.

Primary references:

- [proptest `Config`](https://docs.rs/proptest/1.11.0/proptest/test_runner/struct.Config.html)
  defines cases, persistence, rejection, shrinking, RNG algorithm, and seed.
- [proptest `TestRunner`](https://docs.rs/proptest/1.11.0/proptest/test_runner/struct.TestRunner.html)
  defines direct typed execution and counterexample return.
- [proptest `TestRng`](https://docs.rs/proptest/1.11.0/proptest/test_runner/struct.TestRng.html)
  documents deterministic algorithm-and-seed replay.

## Questions (pre-registered)

1. **Q1 — Holdout projection.** Can proptest use the unchanged
   `proofbound-sampling-contract/1` and
   `proofbound-sampling-observation/1` meanings? **Pass:** the contract retains
   framework/version, fixed seed, successful budget, exact generator closure,
   exact targets, disabled persistence, replay, and shrinking without a
   Rust-only common field. **Falsifier:** reproducibility or observation needs
   an assurance-relevant field—such as RNG algorithm—that the common contract
   cannot represent without ambiguity.
2. **Q2 — Counter authority.** Can an adapter-owned driver report attempted,
   completed, skipped, and shrink counts using stable public typed APIs?
   **Pass:** every counter is derived from typed runner events or an
   adapter-owned predicate boundary with a registered invariant that separates
   generation, rejection, and shrinking. **Falsifier:** a counter requires
   parsing `Display`/stderr, accessing private state, or conflates shrink
   replays with fresh attempts.
3. **Q3 — Counterexample fidelity.** Can a failing proptest emit one bounded
   typed JSON counterexample, retain the actual seed and shrink count, and exit
   nonzero without persistence? **Pass:** independent Rust and Python checks
   reject counterexample substitution and pass/counterexample relabelling.
   **Falsifier:** the minimal failing value or shrink count is unavailable
   without framework internals or app-authored success metadata.
4. **Q4 — Generality decision.** Does this holdout confirm, extend, or reject
   the EXP-0006 contract? **Confirm:** Q1–Q3 pass unchanged. **Extend:** a
   backend-neutral semantic field is required and both earlier frameworks can
   populate it without inference. **Reject:** only a Rust-specific escape hatch
   makes the route pass.

## Procedure

1. Keep the existing Rust evidence manifest and portable receipt byte-exact.
2. Add a research-only proptest generator/predicate module over the allowance
   kernel and a direct `TestRunner` driver pinned by its own lockfile.
3. Run positive and deliberately false properties with persistence disabled,
   a fixed seed, explicit RNG algorithm, and explicit shrink limits.
4. Compare public typed results with the exact EXP-0006 contract and counter
   meanings. Do not parse human runner output.
5. Apply every preregistered substitution in independent Rust and Python
   validation.
6. Record Q1–Q4 independently. Do not modify the common contract merely to
   obtain a passing result.

## Scope

- **In:** proptest `1.11.0`, one bounded allowance-kernel property, fixed seed,
  explicit RNG algorithm, disabled failure persistence, rejections, shrinking,
  typed counterexample, and the EXP-0006 validators.
- **Out:** production adapter/schema changes; replacing the old Rust receipt;
  arbitrary proptest macros; fork/timeouts; persisted regression corpora;
  statistical confidence; universal claims; and Rust fuzzers.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0007-F001 | Reserved for execution. | — | pending |

## Outcome

Q1–Q4 are unanswered. No experiment execution has started.
