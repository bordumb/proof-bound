# Experiment 0005 frozen projection corpus

[Experiment registration](../README.md) ·
[Programme corpus](../../../research/proofbound-language/corpus.md) ·
[Positive cases](cases.json) ·
[Adversarial cases](adversarial-cases.json) ·
[Q1 adversarial cases](q1-adversarial-cases.json) ·
[Q1 completion preregistration](../q1-completion-preregistration.json) ·
[Canonical vectors](canonical-vectors.json)

- **Status:** positive revision 2 and adversarial revision 2 executed;
  Q1 adversarial revision 1 executed; Q1 completion corpus preregistered but
  not executed
- **Baseline:** `295ad63e67bd30cc48eb8c9ee43c612de2c367c6`
- **Positive corpus revision:** 2
- **Adversarial corpus revision:** 2
- **Q1 adversarial corpus revision:** 1
- **Case count:** 20
- **Adversarial case count:** 20
- **Q1 adversarial case count:** 12
- **Q1 completion vertical count:** 3

The corpus freezes tracked registration and portable-fixture bytes from the
experiment baseline. It does not copy generated caches, local tool output, or
external repositories. A source identity is SHA-256 over the exact Git blob
bytes at the baseline commit, not over the mutable working-tree file.

## Roles

The corpus deliberately contains two complementary positive case forms:

1. **Registration projections** preserve the exact current request for Python,
   TypeScript, Kani, Lean, mutation, and distribution routes. Their expected
   status is the aggregate claim status produced by the complete registered
   reference, not a claim that one evidence unit establishes that status alone.
2. **Semantic status projections** point into the independent conformance
   corpus. They freeze the current evidence-algebra outcome without needing to
   execute a backend.

The release-smoke case freezes the complete portable release and envelope used
to test canonical conversion and compiler-internal evidence.

Positive revision 2 adds exact claim-manifest sources to every registration
case. Revision 1 remains the immutable input to the two earlier result files.
The added sources make actual subject, machine meaning, presentation, claim
policy, assumptions, obligations, exclusions, and source roots available to
the Q1 losslessness run; they do not change any registered expected outcome.

## Coverage

| Cases | Meaning covered |
|---|---|
| `IR-PY-001`–`IR-PY-005` | Python example, seeded property, static analysis, mutation, and wheel reproduction |
| `IR-TS-001`–`IR-TS-005` | TypeScript example, seeded property, static analysis, mutation, and npm reproduction |
| `IR-RS-001`–`IR-RS-003` | Kani bounded check, Lean theorem, and Rust mutation registration |
| `IR-SEM-001`–`IR-SEM-006` | theorem, bounded, finite exhaustive, artifact correspondence, trusted transcription, and source refinement semantics |
| `IR-REL-001` | Canonical portable release, cache/reuse fields, graph, policy, closures, status projection, and compiler-internal review evidence |

The inactive Aeneas refinement example is not mislabeled as executed evidence.
Source-refinement semantics are frozen from the positive conformance case;
translation registration is represented by its independently hashed manifest
in `supporting_sources`.

## Equality contract

Each case names a projection profile in `cases.json`. Lists use the ordering or
set semantics of the existing source schema. Exact byte identity applies to the
source fixture and to canonical encodings within one schema version. A future
IR conversion compares semantic projection values; it must not claim that a
new encoding is byte-equal to the old one.

Changing a frozen source, pointer, expected status, projection profile, or blob
identity requires a new corpus revision and journal entry. The adversarial
corpus preregisters omission, duplicate, ordering, family substitution,
evidence-strength upgrade, unknown required semantics, subject/artifact skew,
assumption and cache omission, stale reuse, noncanonical encoding, duplicate
keys, old-schema reinterpretation, required-unknown omission, attribution, and
reported-status attacks. Its exact mutations and expected rejection codes are
frozen before either prototype is implemented.

Adversarial revision 2 corrects IR-ADV-003 before adversarial execution.
Revision 1 tried to reverse a singleton run list and therefore could not alter
its base case. The corrected case changes that source-derived run's command
index while preserving the original ordering invariant and expected rejection
code.

Q1 adversarial revision 1 was frozen after the initial field-preservation and
portable reverse-projection work, but before programme-level graph, policy,
status, and ledger-join validation was extended. It is a separate corpus so
the earlier 20-case adversarial result remains immutable and its preregistered
scope is not rewritten after execution. Both independent implementations have
since rejected all twelve cases with their exact registered codes.

The Q1 completion preregistration was frozen after matrix revision 3 exposed a
different limitation: registration-only language cases cannot prove complete
observation, artifact, cache, and policy semantics. It selects full Python,
TypeScript, and Rust verticals and registers their trace, artifact, and cache
attacks before those captures or trace implementations exist. The Go case is
excluded because it remains the future holdout.

`canonical-vectors.json` freezes five new research-only domain strings and
independent expected digests over three canonical values. These domains do not
alter or reuse any current Proofbound identity domain.
