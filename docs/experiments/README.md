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
| [0010](0010-invalidation-precision/README.md) | Source-retained invalidation precision | Controlled Python, TypeScript, Rust/Lean routes plus two external holdouts | Complete dependency semantics; sound and narrow invalidation; actionable explanation | concluded — declaration-only candidate rejected |
| [0011](0011-dual-frontend-equivalence/README.md) | Dual frontend equivalence | Python, TypeScript, and Rust programme slices in TOML, Proofbound DSL, and Pkl | Canonical equivalence, typed diagnostics, abstraction, evaluator closure | concluded — Q1/Q2 failed; Q3–Q5 bounded pass; frozen controls invalid |
| [0012](0012-effect-checked-replay/README.md) | Effect-checked replay | Hidden-reader falsifier plus bounded mutation, distribution, and subprocess controls | Static authority, mediated trace parity, sound invalidation, subprocess honesty | concluded — Q1–Q5 bounded pass; no OS-sandbox claim |
| [0013](0013-claim-oriented-notification-precision/README.md) | Claim-oriented notification precision | Synthetic claim/finding/uncertainty scenarios; optional practitioner phase | Consequence recall, false escalation, volume, actionable explanations, human validity | concluded — Q1--Q4 bounded pass; Q5 unanswered |
| [0014](0014-specification-falsifiers/README.md) | Specification falsifiers | Finite length-prefixed format contracts and semantic mutants | Typed closure, non-vacuity, consistency, mutant adequacy, independent determinism | concluded — Q1--Q5 bounded pass |
| [0015](0015-assurance-ir-differential-kernel/README.md) | Assurance IR differential kernel | Six joined semantic profiles and a deterministic 500/500 corpus | Cross-component joins, assurance ceilings, differential mutation validation, kernel complexity | concluded — Q1--Q5 bounded pass |
| [0016](0016-native-canonical-parser/README.md) | Native canonical parser | Canonical `.pb` parser/serializer and deterministic research bytecode | Native syntax, proof-search/check separation, dual compilation, assurance scope, complexity | concluded — Q1--Q5 bounded pass |
| [0017](0017-mixed-language-migration/README.md) | Mixed-language migration | Native research bytecode called from Python and TypeScript across one mixed assurance graph | Foreign ABI honesty, assurance ceilings, selective migration, independent agreement | concluded — Q1--Q5 bounded pass |
| [0018](0018-os-enforced-effects/README.md) | OS-enforced effects and sound invalidation | Python, Node, and Rust processes under one macOS enforcement boundary | Ambient authority denial, exact reuse identity, independent receipts, cross-language feasibility | concluded; revise |
| [0019](0019-batched-enforcement-latency/README.md) | Batched enforcement latency | EXP-0018 Python, Node, and Rust corpus under a concurrent isolated scheduler | Latency repair, per-run isolation, receipt completeness, independent validation | concluded; pass |
| [0020](0020-linux-enforcement-portability/README.md) | Linux enforcement portability | EXP-0018 effect contract compiled to a Linux Landlock/seccomp candidate | Semantic policy parity, fail-closed availability, independent policy validation | concluded; unanswered |
| [0021](0021-windows-enforcement-portability/README.md) | Windows enforcement portability | EXP-0018 effect contract compiled to a Windows AppContainer candidate | Semantic policy parity, fail-closed availability, independent policy validation | concluded; unanswered |
| [0022](0022-linux-enforcement-confirmation/README.md) | Native Linux enforcement confirmation | Frozen EXP-0020 corpus on a Landlock ABI 4+ Linux host | Live permitted workloads, authority denial, non-reuse, independent validation | concluded; revise |
| [0023](0023-windows-enforcement-confirmation/README.md) | Native Windows enforcement confirmation | Frozen EXP-0018 corpus and EXP-0021 policy on Windows 11 ARM64 | Live conjunctive enforcement, denial, non-reuse, independent validation | concluded; revise |
| [0024](0024-linux-loader-closure/README.md) | Exact Linux loader execution closure | EXP-0022 runtime-execution falsifier on Landlock ABI 7 | Exact ELF interpreter authority, positive recovery, denial preservation | concluded; pass |
| [0025](0025-windows-initialization-closure/README.md) | Exact Windows initialization closure | EXP-0023 pre-entry DLL-initialization falsifier on Windows 11 ARM64 | Exact PE/profile/object authority, positive recovery, denial preservation | concluded; revise |
| [0026](0026-windows-output-network-confirmation/README.md) | Exact Windows output and network confirmation | EXP-0025 LF/CRLF and ambiguous network-denial falsifiers | Binary output parity, reachable denial oracle, retained initialization closure | concluded; revise |
| [0027](0027-windows-wfp-drop-attribution/README.md) | Windows WFP drop attribution | EXP-0026 timeout/non-delivery observations | Read-only kernel attribution, typed network outcomes, exact subject/flow binding | concluded; revise |

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
