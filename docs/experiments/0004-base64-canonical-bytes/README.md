# Experiment 0004: base64 canonical bytes

- **Status:** concluded
- **Registered:** 2026-08-31
- **Started / concluded:** 2026-08-31 / 2026-08-31
- **Subject:** `base64` crate `0.22.1` (crates.io), source archive 81,597
  bytes, SHA-256
  `72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6`,
  vendored locally at `other_repos/base64-0.22.1`
- **Proofbound:** `f728f6e9da2f210ce51c62cba151590650f7f5c3`
- **Operator:** Codex (GPT-5)

## Why this crate

One of the most-downloaded crates in the ecosystem, and a canonical byte
boundary in miniature: encode/decode round-trip, strict-mode rejection of
non-canonical encodings (trailing bits, improper padding) — a bug class with
real security history, since non-canonical base64 acceptance has enabled
signature-bypass issues elsewhere. Exercises the Tier 0 → Tier 1 ladder and
Pattern A on bytes we do not control.

## Questions (pre-registered)

1. **Q1 — Tier 0 in a day.** Ledger from the crate's existing tests, honest
   board, no proof toolchains. Pass: `proofbound status` renders;
   wall-clock recorded.
2. **Q2 — Tier 1 stands alone.** Kani bounded harnesses for
   decode∘encode = identity and canonical rejection over registered bounded
   domains. Pass: claims render `BOUNDED_CHECKED` with the domain stated in
   the claim language; no Lean involved.
3. **Q3 — Pattern A on foreign fixtures.** An independent Lean decoder over
   a registered fixture corpus (valid and non-canonical cases), with an
   acceptance-implies-meaning theorem and digest binding. Pass: at least one
   claim renders `ARTIFACT_BOUND`; the Lean decoder shares no code with the
   crate.
4. **Q4 — Sharp edges surface as claims.** Does the honest board express the
   crate's real semantic modes (indifferent vs strict padding/trailing-bit
   handling) as distinct claims and assumptions rather than prose caveats?
   Pass: an engine-mode confusion scenario is representable as a claim that
   is visibly `OPEN` or scoped, not silently absorbed.

## Scope

- In: standard and URL-safe alphabets, strict and indifferent engines,
  encode/decode round-trip and canonicality.
- Out: SIMD/acceleration paths; alphabet customization beyond the two
  standard ones; streaming APIs; upstreaming changes.

## Journal (append-only)

- **2026-08-31** — Pre-registered. Not started.
- **2026-08-31** — START. Pinned the exact `base64` 0.22.1 crate archive
  (81,597 bytes; SHA-256
  `72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6`),
  local vendor destination, and Proofbound commit
  `f728f6e9da2f210ce51c62cba151590650f7f5c3`. No subject archive was
  extracted, read, or built before this running record was committed.
- **2026-08-31** — Established the untouched subject baseline. After fetching
  the exact declared development dependencies once, the locked offline Cargo
  test run passed all 217 tests (179 library, 6 `encode`, 7 `decode`, and 25
  documentation tests). The crates.io archive contains no `Cargo.lock`; that
  is an ordinary library-crate bootstrap fact, not evidence of subject drift.
- **2026-08-31** — Reached the first rendered Tier 0 board after 16 minutes
  22 seconds. Five mode-specific claims rendered
  `TESTED / MODEL_ONLY / ASSUMED`; external strict-engine selection remained
  visibly `OPEN / MODEL_ONLY / NONE`.
- **2026-08-31** — Exercised the mode boundary explicitly. Padding acceptance
  and trailing-bit tolerance are independent configuration choices, so the
  ledger keeps RFC vectors, canonical padding, indifferent padding, strict
  trailing-bit rejection, and forgiving trailing-bit examples as separate
  claims rather than one broad “base64 correctness” claim.
- **2026-08-31** — Added four Kani 0.67 harnesses on isolated subject commit
  `900201272473e40b7dccc8c5737f5161cea59b86`: standard and URL-safe
  round trips for byte strings of length at most two, plus strict standard and
  URL-safe rejection of registered noncanonical suffixes. All four passed
  with CaDiCaL and unwind 6 over a registered combined domain of 140,290
  cases. No Lean evidence was present.
- **2026-08-31** — Mutated the strict URL-safe engine to permit trailing bits.
  The focused harness then failed, and a full Proofbound check rendered the
  bounded claim `INVALID` and blocked publication. The mutation was reverted
  in the isolated snapshot.
- **2026-08-31** — Rejected the first Pattern A result after review. It
  rendered `ARTIFACT_BOUND`, but the evidence association named a theorem
  about corpus meaning that did not mention the digest while a separate digest
  theorem was exempt from the claim. The canonical-artifact checker supplied
  the binding booleans, so the framework admitted a relationship it had not
  established. This is a framework security-design divergence, not a passing
  result.
- **2026-08-31** — Strengthened the Pattern A case on isolated commit
  `c56520b56b8aa8276f274ba6dd4d3c40bbc3ffd4`. The exact theorem
  `Base64Fixture.Claims.publishedArtifactSoundness` now conjoins the meaning
  of all fourteen cases with a kernel-evaluated SHA-256 equality for the exact
  131-byte artifact (`sha256:237fc299e27c298c1d76a37dd13d9ecd4d7e33fe9f26b8394cb0a9174b6806d5`).
  Matched Proofbound binaries rendered `PROVED / ARTIFACT_BOUND / NONE`; the
  theorem used only `Quot.sound` and `propext`, with statement identity
  `sha256:54b65e3dc6c0078ee0db310da2182af8a44ff93a252eaf9089a0b86486ae84dc`.
  The semantic closure is
  `sha256:5e436d063c1fc33cfd4563c51971175d99680fac88579498118f07ab1dd741e2`;
  the matched release payload is
  `sha256:46a11f0ebf009725c577aea2670b48aafca1a8e4ae78c86baee4afabb3c0ebaf`.
  This validates the mechanism, but not Q3's “foreign fixtures” premise: the
  B64F envelope and assembled corpus are experiment-owned.
- **2026-08-31** — The bounded pilot exposed two same-shape receipt defects:
  the compiler replaced the registered solver with a placeholder and emitted
  no unwind bounds, and reader output replaced the checked property with the
  domain text. Proofbound 0.6 now projects the exact registered solver and
  nonzero per-harness unwind bounds and renders the property followed by its
  registered finite domain. Core and verifier reject empty, missing, extra, or
  zero unwind coverage; the producer rejects cached solver or unwind values
  that differ from the registered model unit.
- **2026-08-31** — Deferred four wire-shape defects to an explicit versioned
  receipt migration: registered model assumptions have no receipt field;
  unknown peak memory becomes zero; reader-facing `public_language` replaces
  the internal statement; and the adapter's exact command sequence collapses
  to one representative provenance command. None was patched by silently
  changing the `/1` schemas.
- **2026-08-31** — TIMING CORRECTION. The earlier 16m22 measurement ended at
  the first rendered board. The full Q1 interval from the Tier 0 start at
  02:20:58 through the final corrected board commit
  `a7fbb6ec4e1a025cf9ad393a82683dfaf1524dc6` at 02:46:50 was 25m52. Q1 uses
  the latter completion time.
- **2026-08-31** — FINAL BOUNDED RERUN. A fresh matched-binary run on clean
  subject commit `900201272473e40b7dccc8c5739f5161cea59b86` completed in
  56.913 seconds. Evidence
  `sha256:56f047ff1e40a707a14a18be3616f7b7443e166f1f7b0ea69294d44388ca705e`
  records Kani 0.67, CaDiCaL, exactly four harnesses with unwind 6 each, and
  the 140,290-case domain. Status is
  `BOUNDED_CHECKED / MODEL_ONLY / NONE`; its public language retains the
  property and appends the registered domain. No Lean evidence is present.
- **2026-08-31** — CLOSE. Q1 PASS, Q2 PASS, Q3 FAIL, Q4 PASS. Seven
  divergences are indexed and disposed by ADR 0011. All subject work remained
  on local `dev-proof-bound-experiment` branches; no remote action or
  publication occurred.
- **2026-08-31** — POST-CLOSE RELEASE CHECK. The first Proofbound 0.6 producer
  release failed the standalone verifier with `PBV_NON_CANONICAL`: producer
  canonical JSON retained `provenance.additional_closures: []`, while the
  verifier's typed canonical form omitted the empty optional collection. This
  does not change Q2, whose registered criterion is status plus bounded public
  language without Lean, but no portable Q2 release is claimed from that
  failed run. A focused normalization fix and standalone rerun are pending.
- **2026-08-31** — RE-CLOSE. The producer now omits the empty
  `additional_closures` collection from both canonical evidence and cache-key
  material, with cross-implementation regressions. A fresh release from clean
  subject commit `900201272473e40b7dccc8c5739f5161cea59b86` is
  `receipt-consistent` under the bundled standalone verifier: payload
  `sha256:03e6e481ed1c169d2103a9f72e81bae496c63f1cb7caa8552e8e8e52129084d1`,
  raw compiled receipt
  `sha256:7cf9e3be600a0f1d92c4091bcd730157a2abf6c7a44d40b8da34812835a77026`.
  The cache key verifies and status remains
  `BOUNDED_CHECKED / MODEL_ONLY / NONE`. Outcomes remain Q1 PASS, Q2 PASS,
  Q3 FAIL, Q4 PASS; eight divergences are indexed and disposed by ADR 0011.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0004-F01 | The untouched `base64` 0.22.1 archive passes its complete locked, offline test suite after one exact dependency bootstrap. | 217 passing tests; archive SHA-256 `72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6` | baseline |
| EXP-0004-F02 | A mode-specific Tier 0 board is feasible in well under a day without proof tooling. | 25m52s start-to-final-board; first render at 16m22s; isolated commit `a7fbb6e`; five `TESTED` claims and one `OPEN` claim | Q1 `PASS` |
| EXP-0004-F03 | The crates.io library archive has no lockfile, so exact offline closure requires a one-time fetch of its exact resolved development dependencies. | resolved lock SHA-256 `cee37732975a1ffc1f956d3d05b6edf1baec72841cfabc384a21b02b3bfa0275` | case-record |
| EXP-0004-F04 | Padding mode and trailing-bit tolerance are orthogonal; external selection of the intended strict engine is an honest open obligation. | distinct Tier 0 claims plus `BASE64-STRICT-ENGINE-SELECTION-001` as `OPEN` | Q4 `PASS` |
| EXP-0004-F05 | Four Kani harnesses cover 140,290 registered finite cases across two alphabets, short round trips, trailing-bit rejection, and missing-padding rejection. | Kani 0.67, CaDiCaL, unwind 6 each; isolated commit `9002012`; fresh evidence `sha256:56f047ff1e40a707a14a18be3616f7b7443e166f1f7b0ea69294d44388ca705e`; four of four harnesses pass | Q2 `PASS` |
| EXP-0004-F06 | Enabling trailing-bit tolerance in the strict URL-safe engine is detected by both the focused harness and Proofbound publication gating. | focused harness failure; full claim `INVALID`; publication blocked | mutation witness |
| EXP-0004-F07 | Bounded receipts previously discarded the registered solver and unwind bounds. | placeholder solver and empty unwind map in the first receipt | `EXP-0004-D01`; fixed in 0.6 |
| EXP-0004-F08 | Bounded status previously displayed only the finite domain and dropped the property being checked. | first compiled status record | `EXP-0004-D02`; fixed in 0.6 |
| EXP-0004-F09 | Four observed facts cannot be represented honestly in the current `/1` receipt shape. | model assumptions absent; unknown memory serialized as zero; public/internal statements collapsed; multi-command execution collapsed | `EXP-0004-D03`–`D06`; ADR 0011 |
| EXP-0004-F10 | Canonical-artifact admission can accept checker-authored binding booleans even when the associated theorem does not mention the artifact digest. | deliberately rejected first Pattern A result | `EXP-0004-D07`; ADR 0011 |
| EXP-0004-F11 | A corrected exact digest-conjoined theorem can be checked in the Lean kernel and admitted as assumption-free artifact-bound evidence. | commit `c56520b`; fixture SHA-256 `237fc299e27c298c1d76a37dd13d9ecd4d7e33fe9f26b8394cb0a9174b6806d5`; statement SHA-256 `54b65e3dc6c0078ee0db310da2182af8a44ff93a252eaf9089a0b86486ae84dc`; `PROVED / ARTIFACT_BOUND / NONE` | positive mechanism result |
| EXP-0004-F12 | The fixture case was not foreign in the pre-registered sense: the envelope and assembled corpus were produced by the experiment, although source literals came from the pinned subject and the decoder shared no subject code. | fixture provenance ledger and isolated tree review | Q3 `FAIL` |
| EXP-0004-F13 | The existing imperative SHA-256 implementation was convenient for native execution but did not kernel-reduce over the 131-byte fixture; a temporary structurally recursive evaluator did. | three kernel-checked intermediate-state decisions and final digest equality | case-record |
| EXP-0004-F14 | Producer and standalone-verifier canonicalization disagreed when `provenance.additional_closures` was empty. | first 0.6 Q2 release failed `PBV_NON_CANONICAL`; fixed rerun payload `sha256:03e6e481ed1c169d2103a9f72e81bae496c63f1cb7caa8552e8e8e52129084d1` is `receipt-consistent` and its cache key verifies | `EXP-0004-D08`; bug fixed with cross-implementation regression |

## Outcome

1. **Q1 — PASS.** `proofbound status` rendered the first Tier 0 board after
   16m22s and the corrected final board after 25m52s total.
2. **Q2 — PASS.** A fresh matched-binary run rendered
   `BOUNDED_CHECKED / MODEL_ONLY / NONE` for the four exact Kani harnesses over
   140,290 registered cases, retained both the property and domain in public
   language, and used no Lean evidence. The negative mutation invalidated the
   claim and blocked publication. After repairing an independently detected
   canonical-empty-collection bug, a fresh bundled standalone-verifier run is
   also `receipt-consistent`.
3. **Q3 — FAIL.** The corrected mechanism produced assumption-free,
   digest-conjoined `ARTIFACT_BOUND` evidence using an independent Lean
   decoder, but the exact B64F artifact and assembled corpus were controlled by
   the experiment. That does not satisfy the pre-registered question about
   foreign fixtures.
4. **Q4 — PASS.** The board makes the padding/trailing-bit modes distinct and
   leaves external strict-engine selection visibly `OPEN`.
