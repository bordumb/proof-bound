# Experiments

Structured records of Proofbound pilots and use-case tests. Each experiment
answers pre-registered questions about the framework against a real subject —
a reference repository, an external crate, or Proofbound itself.

## Index

| # | Experiment | Subject | Tests | Status |
|---|---|---|---|---|
| [0001](0001-matrix-math-release-verification/README.md) | Matrix Math release verification | `matrix-math-publish` (GitHub) | Pattern A at scale; independent release verification; producer-absent boundary | concluded |
| [0002](0002-auths-proof-algebra-kernel/README.md) | Auths Proof algebra kernel | `auths-proof` repo | §11.3 manifest inversion; per-harness Kani inventory | concluded |
| [0003](0003-semver-precedence/README.md) | semver precedence | `semver` crate (crates.io) | Tier 0 brownfield UX; Pattern B on foreign code | concluded |
| [0004](0004-base64-canonical-bytes/README.md) | base64 canonical bytes | `base64` crate (crates.io) | Tier 0→1 ladder; Pattern A on foreign bytes | concluded |
| [0005](0005-assurance-ir-extraction/README.md) | Assurance IR extraction | Proofbound repository and conformance corpus | Shared semantic kernel; evidence-family boundaries; producer/verifier parity | concluded — Q1 failed at 15/16 rows; Q2–Q5 bounded pass |
| [0006](0006-explicit-sampling-contract/README.md) | Explicit sampled-property contract | Hypothesis and fast-check reference properties | Portable sampling semantics; observation authority; honest legacy migration | concluded |
| [0007](0007-rust-sampling-holdout/README.md) | Rust sampled-property holdout | allowance kernel and proptest 1.11.0 | Third-ecosystem generality; counter authority; contract confirmation or falsification | concluded |
| [0008](0008-layered-sampling-model/README.md) | Layered sampling model | EXP-0006/0007 three-framework results | Common intent; typed backend plans; authority-indexed facts; targeted uncertainty | concluded |
| [0009](0009-generated-evidence-algebra/README.md) | Generated evidence algebra | Proofbound status corpus and Assurance IR candidate | Explicit derivation traces; forbidden coercions; independent generated differential checking | concluded — Q1–Q5 passed over the registered 500/500 corpus |
| [0010](0010-invalidation-precision/README.md) | Source-retained invalidation precision | Controlled Python, TypeScript, Rust/Lean routes plus two external holdouts | Complete dependency semantics; sound and narrow invalidation; actionable explanation | planned — preregistered, not executed |

Statuses: `planned` (pre-registered, not started) · `running` · `concluded` ·
`abandoned` (a status, not a deletion — the journal stays).

## Rules

1. **Pre-registration is a commit.** An experiment's Questions section lands
   in git before its first journal entry. That commit is the ordering
   evidence — the lesson of ADR 0001, applied forward.
2. **Every divergence gets a disposition.** Each finding is dispatched to
   `spec-change`, `adr`, `case-record`, `bug (fixed)`, or
   `accepted-limitation`, and indexed in [DIVERGENCES.md](DIVERGENCES.md).
   This is the Specification 0001 M5 acceptance evidence, in one file.
3. **Cite digests, not vibes.** Subjects are pinned by full commit or crate
   version; artifacts by content address. Large artifacts go to the CAS;
   the experiment folder holds pointers.
4. **Journals are append-only.** Corrections are new entries, never edits.
5. **Cross-repo pilots keep their record here.** Work happens in the subject
   repository; the learning belongs to proof-bound.

New experiments copy [TEMPLATE.md](TEMPLATE.md). Public-facing audit reports
graduate to [docs/audits/](../audits/README.md); the raw experiment record
stays here.

Experiments with more than a few execution entries should keep their immutable
registration and outcome in `README.md`, chronological observations in an
append-only `JOURNAL.md`, and machine-readable artifacts or results in bounded
subdirectories. The template documents the split; existing concluded
experiments need not be mechanically rewritten.
