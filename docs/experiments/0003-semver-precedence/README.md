# Experiment 0003: semver precedence

- **Status:** concluded
- **Registered:** 2026-08-31
- **Started / concluded:** 2026-08-31 / 2026-08-31
- **Subject:** `semver` crate version `1.0.28` from crates.io; exact `.crate`
  archive SHA-256
  `8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd`
  (33,064 bytes), to be vendored at `other_repos/semver-1.0.28`
- **Proofbound:** `04cf8111fe31648997a36d417531566ddd6b8756`
- **Operator:** Codex (GPT-5)

## Why this crate

`semver` is depended on by cargo itself and much of the ecosystem, its
precedence kernel is small, pure, and effect-free — plausibly inside the
Aeneas-translatable subset as written — and its central claims (SemVer 2.0.0
precedence rules) are subtle, load-bearing, and proved by nobody against the
shipping code. First test of the full ladder on code we do not own.

## Questions (pre-registered)

1. **Q1 — Tier 0 in a day.** Starting from the crate's existing test suite,
   can a useful Tier 0 ledger (claims registered, assumptions named, tests
   bound, honest board) be reached in one working day with no proof
   toolchains installed? Pass: `proofbound status` renders the board;
   wall-clock recorded.
2. **Q2 — Aeneas-subset fit.** Is the precedence comparison kernel
   translatable as-is, or does it require a pure-kernel extraction refactor
   first? Pass: either outcome, with the lines-changed delta recorded — this
   measures Pattern B's real entry cost on foreign code.
3. **Q3 — Pattern B end-to-end.** Can a named refinement theorem connect the
   translated comparison to a handwritten Lean precedence model (numeric
   identifiers lower than alphanumeric, prerelease below release, build
   metadata ignored, total order)? Pass: a claim renders
   `PROVED · REFINED` with representation premises enumerated.
4. **Q4 — Mutation witnesses bite.** Do registered mutation witnesses catch
   seeded precedence bugs (e.g. dropping the numeric-lower rule, comparing
   build metadata)? Pass: each seeded mutation flips a green claim.

## Scope

- In: version parsing and precedence comparison (`Version`, `Prerelease`
  ordering).
- Out: `VersionReq`/range matching (a much larger surface); upstreaming
  anything to the crate; performance claims.

## Journal (append-only)

- **2026-08-31** — Pre-registered. Not started.
- **2026-08-31** — START. Selected the newest locally cached crates.io
  release, `semver` `1.0.28`; pinned its exact 33,064-byte crate archive at
  SHA-256 `8a7852d0…1cd`; pinned Proofbound at
  `04cf8111fe31648997a36d417531566ddd6b8756`. No subject file was extracted,
  read, built, or modified before this START record.
- **2026-08-31** — VENDOR AND BASELINE. Extracted the exact cached crate under
  the gitignored `other_repos/` boundary and performed all execution in
  isolated temporary Git repositories on branch
  `dev-proof-bound-experiment`. The unmodified subject passed 34 ordinary
  tests and four doctests; the only diagnostics were pre-existing
  `test_node_semver` check-cfg warnings.
- **2026-08-31** — TIER 0. From `proofbound init` to a clean rendered board
  took 5 minutes 25 seconds. Four narrow claims over the upstream
  `test_version::test_spec_order` examples rendered
  `TESTED · MODEL_ONLY · ASSUMED`; the documented build-metadata behavior was
  separately registered as `OPEN · MODEL_ONLY · ASSUMED` because its only
  upstream executable example is a doctest, not a selectable ordinary test.
  Every claim displayed its generalization obligation and exclusions.
- **2026-08-31** — ROOT-PACKAGE CLOSURE. The initial fresh check failed before
  evidence execution because a root Cargo package was normalized to the
  invalid glob `/**`. A broad `src/**`/`tests/**` workaround demonstrated the
  ledger without weakening its closure. The generic Proofbound fix now emits
  the canonical recursive pattern `**` for a root package and has a root and
  nested-package regression; the cheap locked preflight passed after the fix.
  The overlay also added `/.proofbound/` to its local `.gitignore`, keeping
  verify-only receipts from making the subject appear dirty.
- **2026-08-31** — TRANSLATION FIT. A superficially plausible Charon selector
  for the inherent `Version::cmp_precedence` method exited zero while selecting
  no functions; the correct inherent selector is unsupported. A four-line
  free wrapper produced a real closure, after which Aeneas failed on
  `core::str::pattern::Pattern`, reached through `Prerelease::cmp`.
- **2026-08-31** — PURE-KERNEL EXTRACTION. The smallest successful tested
  refactor (not a proof of global minimality) changed 184 production lines:
  180 additions and four deletions. It introduced an explicit byte/index-loop
  kernel and delegated shipping precedence to it. Charon/Aeneas emitted 11
  local function records, zero external or opaque-local functions, one local
  ordering type, and axiom/sorry/admit-free Lean. The upstream suite remained
  green and an unshipped differential audit agreed on all 625 ordered pairs of
  a 25-version corpus. Q2 therefore passes with the measured refactor outcome.
- **2026-08-31** — REFINEMENT. The generated Lean compiled, but four generated
  loops are `partial_fixpoint` definitions and the translated API returns
  `Result`. No theorem proving bounds, termination, success, and equality to a
  handwritten model was completed. Q3 is unanswered. The audit also corrected
  the intended statement: build-insensitive precedence is a total preorder on
  concrete `Version` values, or a total order only on the precedence projection
  / quotient modulo build metadata.
- **2026-08-31** — MUTATION BASELINE. The unmodified upstream suite does not
  catch removal of the numeric-lower-than-nonnumeric branch: its
  `alpha.1 < alpha.beta` example remains true under ASCII fallback. The minimal
  killing pair is prerelease identifier `1` versus `-`. Comparing build
  metadata inside `cmp_precedence` leaves all 34 ordinary tests green but flips
  the existing doctest, for a 37/38 full-suite result.
- **2026-08-31** — REGISTERED WITNESSES. Added two exact named witnesses and a
  strict mutation registry only in an isolated subject branch. Clean fresh
  check produced two admitted `TESTED · MODEL_ONLY` claims and exact mutation
  inventory. Seeding either shipping mutation in a separate snapshot made its
  exact witness fail, removed the evidence receipt, changed the applicable
  claim to `INVALID`, and blocked publication. Both mutations shared one unit,
  so either failure conservatively invalidated both claims; separate units
  would provide finer attribution. Q4 passes at claim level without a core
  change.
- **2026-08-31** — CLOSE. Q1 PASS, Q2 PASS, Q3 UNANSWERED, Q4 PASS. Elapsed
  operator wall time was about 0.32 hours with the translation and mutation
  work parallelized. Six divergences are indexed and disposed by ADR 0010; no
  subject change was upstreamed, and no remote action occurred.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0003-F01 | The unmodified `semver` 1.0.28 suite is green and provides a useful but finite canonical precedence example. | 34 ordinary tests + 4 doctests pass; `test_spec_order` is the exact registered Tier-0 node. | `case-record`; Q1 baseline |
| EXP-0003-F02 | A useful five-claim Tier-0 board was reachable in 5m25s, with four tested examples and the build-insensitive claim honestly open. | Clean fresh check in isolated branch `dev-proof-bound-experiment`; exact Cargo/libtest receipt; mandatory assumption and gap sections rendered. | `case-record`; Q1 pass |
| EXP-0003-F03 | Root-level Cargo packages produced an unsafe `/**` transitive-closure pattern. | Initial check returned `PB-CLOSURE-0001`; reusable helper now maps root to `**` and nested package to `crates/member/**`; regression and preflight pass. | `adr (#10)`; generic product bug fixed |
| EXP-0003-F04 | `check` receipts require an ignored `.proofbound/` path in an adopted repository to preserve a clean status. | Without the one-line ignore, status reported dirty immediately after check; with it, the same board reported clean. | `case-record`; one-line brownfield adoption cost |
| EXP-0003-F05 | Charon can exit zero for `semver::Version::cmp_precedence` while selecting an empty translation. | Aeneas report contained zero functions/types; correct inherent selector is explicitly unsupported. | `adr (#10)`; require nonempty exact inventory, never exit status alone |
| EXP-0003-F06 | A selector shim is insufficient: shipping prerelease comparison reaches an Aeneas-unsupported generic string-pattern path. | Wrapper closure was nonempty; Aeneas exit 2 at `core/src/str/pattern.rs:99`. | `case-record`; pure-kernel refactor required |
| EXP-0003-F07 | The smallest successful tested pure-kernel extraction was +180/−4 production lines. | 11 local functions, 0 external, 0 opaque-local; generated Lean compiles; 38/38 upstream checks and 625-pair differential corpus pass. | `adr (#10)`; Q2 pass, measured foreign-code entry cost |
| EXP-0003-F08 | Translation did not complete the refinement proof: loop termination, bounds, `Result.ok`, and semantic equivalence remain. | Four generated `partial_fixpoint` loops; no named `semver_cmp_precedence_refines_model` theorem or receipt. | `accepted-limitation`; Q3 unanswered |
| EXP-0003-F09 | “Build ignored” is not a total order on concrete versions whose equality includes build metadata. | Versions differing only in build compare precedence-equal while remaining unequal concrete values. | `adr (#10)`; restate as total preorder or quotient/projection order |
| EXP-0003-F10 | The upstream suite does not catch removal of the numeric-lower rule, while the build-metadata mutation is caught only by a doctest. | Numeric mutant: 38/38 upstream checks remain green; build mutant: 34 ordinary green, one doctest fails. | `adr (#10)`; add exact ordinary witnesses |
| EXP-0003-F11 | Exact registered witnesses make both seeded shipping mutations fail closed at claim level. | Clean: two TESTED claims, evidence `sha256:6e995a22…b4ba1`. Each mutant: witness exit 101, claim INVALID, `PB_CORE_EVIDENCE_MISSING`, publication blocked. | `case-record`; Q4 pass |
| EXP-0003-F12 | One evidence unit spanning both mutations gives conservative unit-level rather than mutation-level attribution. | Either witness failure removes the shared receipt and invalidates both attached claims. | `adr (#10)`; split registries/units when per-mutation isolation is required |

## Outcome

1. **Q1 — PASS.** A useful five-claim Tier-0 ledger and honest board were
   reached in 5m25s. Four existing-test examples are TESTED; the documented
   build behavior remains visibly OPEN rather than borrowing doctest prose as
   ordinary test evidence.
2. **Q2 — PASS.** Shipping comparison is not Aeneas-translatable as written.
   A successful pure-kernel extraction required +180/−4 production lines;
   that measured outcome is explicitly accepted by the registered question.
3. **Q3 — UNANSWERED.** Axiom-free generated Lean compiles, but no named
   refinement theorem discharges termination, bounds, result-success, and
   representation premises. No `PROVED · REFINED` status is claimed.
4. **Q4 — PASS.** Both exact registered witnesses are green on clean source.
   Each separately seeded shipping mutation flips its applicable green claim
   to INVALID and blocks publication. This is empirical mutation sensitivity,
   not formal proof.
