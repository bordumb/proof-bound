# Experiment 0002: Auths Proof algebra kernel

- **Status:** concluded
- **Registered:** 2026-08-31
- **Started / concluded:** 2026-08-31 / 2026-08-31
- **Subject:** `auths-proof` repository at commit
  `95c9d4583e10fdc3ffaecc0a96790bec1c922640` (branch
  `dev-proof-bound-experiment`), translation source-closure digest at START
  `616fcfae33e76019a1e9c59dfc886375b8e2f92dbf381fb2074a7df7bfa5f741`
- **Proofbound:** `bc00b8f83683a0633debe2c8597fae9900e0bd09`
- **Operator:** Codex (GPT-5)

## Why this subject, why this unit

Auths Proof is the reference for Pattern B, and its known architectural debt
is that the qualification manifest cross-checks hard-coded orchestration
constants rather than driving them (Specification 0001 §11.3 inversion
requirement, graded `redesign` in §15.2). The algebra kernel
(`core/crates/auths-algebra-kernel`) is its smallest translation unit — two
translated functions, five Kani harnesses — so it stresses the inversion at
minimum blast radius. The other four translation units are explicitly out of
scope until this one answers.

## Questions (pre-registered)

1. **Q1 — Manifest-only translation.** Can the algebra kernel's
   Charon/Aeneas invocation be derived entirely from a
   `proofbound-translation-unit/1` manifest, with zero edits to xtask
   constants? Pass: two clean reproduction runs from the manifest alone are
   byte-identical under the declared normalization.
2. **Q2 — Quarantine declared, not conventional.** Are the unit's template
   axioms (and any external bridges) fully declarable in the manifest with
   exact per-file counts, validated fail-closed? Pass: an undeclared template
   axiom or count drift fails the build.
3. **Q3 — Claim parity.** Can the algebra claims currently in
   `formal/assurance-manifest-v1.toml` be expressed as `proofbound-claim/1`
   records whose derived facets match the meaning of the existing ledger's
   statuses? Pass: statuses agree, or every disagreement is a recorded
   finding.
4. **Q4 — Per-harness Kani inventory.** Can the five algebra-kernel harnesses
   be inventoried per-harness from tool metadata and matched bidirectionally
   against the manifest, replacing the package-level attribute grep? Pass: a
   deliberately added ungated harness fails closed.

## Scope

- In: `auths-algebra-kernel` only — translation, quarantine, claims, Kani.
- Out: the model, authority, bounded-policy, and lifecycle units; auths-proof
  CI integration; any change to auths-proof's own release machinery.

## Journal (append-only)

- **2026-08-31** — Pre-registered. Not started.
- **2026-08-31** — START. Created the required local-only throwaway branch
  `dev-proof-bound-experiment` at subject commit
  `95c9d4583e10fdc3ffaecc0a96790bec1c922640`; verified the committed
  translation closure's internal digest
  `616fcfae33e76019a1e9c59dfc886375b8e2f92dbf381fb2074a7df7bfa5f741`
  and its file SHA-256 `9bb83f20310acee4edbeb0b78ec2474171789e1cc976b7fc34b742e2335fdacc`;
  pinned Proofbound at `bc00b8f83683a0633debe2c8597fae9900e0bd09`.
- **2026-08-31** — CAPABILITY. Charon and Aeneas executables are absent;
  the pinned extraction Rust toolchain and Aeneas source checkout are present.
  The native qualification command stopped after its toolchain-lock check and
  requested the missing Charon binary. Nothing was installed or fetched.
- **2026-08-31** — MANIFEST INVERSION. Reconstructed the algebra commands
  from xtask. The qualification manifest declares result counts and symbols,
  but the Cargo manifest, start set (including `RootLinkage`), LLBC mapping,
  Aeneas destination/subdirectory, flag vectors, and output map remain Rust
  constants. Q1 therefore fails independently of the unavailable execution.
- **2026-08-31** — QUARANTINE. The algebra output currently has two local,
  zero external, zero opaque functions and no template/bridge/axiom files.
  Declared template count drift is checked, but generated-file enumeration is
  itself hardcoded and an extra undeclared template file is not traversed.
  Q2 therefore fails the full bidirectional criterion.
- **2026-08-31** — CLAIM PARITY. The old ledger contains eight claims tied to
  algebra symbols: six `proved` threshold claims and two `qualified` rich
  refinement claims. Those labels collapse theorem status, Rust linkage, and
  assumptions. There is no standalone ledger claim for either function in the
  two-function translation unit; three baseline claims are about handwritten
  `thresholdTwo`, and the other three use common-origin generated Lean rather
  than a Rust refinement. Candidate Proofbound records can state the split,
  but missing translation execution prevents fresh derived facets, so Q3
  remains unanswered rather than treating file citations as receipts.
- **2026-08-31** — KANI. Kani 0.67 metadata returned the exact five registered
  harness IDs. A canonical Proofbound inventory request matched them in about
  2.1s. Adding a sixth harness only in an isolated `/tmp` copy made the same
  request return `success:false`, `evidence:null`, and `PB-KANI-1006` naming
  the extra harness. The pinned Auths branch remained clean.
- **2026-08-31** — CLOSE. Q1 failed, Q2 failed, Q3 was unanswered, and Q4
  passed. Eight divergences are indexed and disposed by ADR 0009. No Auths
  source commit, remote action, tool installation, or Proofbound core fork was
  made; elapsed operator wall time was about 0.2 hours.
- **2026-08-31** — POST-CLOSE CAPABILITY INTERVENTION. At the operator's
  direction, installed the exact pinned Charon and Aeneas revisions as
  reusable user-wide tools under `~/.local`, with stable PATH symlinks.
  Charon `0.1.225` at `527ea8e3…d59` has binary SHA-256 `b9f9c9eb…5a8e`;
  Aeneas `3a8586fa` at `3a8586fa…b31` has binary SHA-256
  `e7c9f759…312d`. No unpinned substitute was used.
- **2026-08-31** — SUBJECT PORTABILITY REPAIR. The first real qualification
  attempt exposed a macOS build error: `rustix` device IDs and standard-library
  metadata device IDs have different integer types on this platform. A
  fail-closed checked conversion helper and regression test were committed on
  the required local Auths branch at
  `ad4f02c` (`fix: normalize Unix stat identity across platforms`). The
  dedicated update door rebound only the translation closure and its three
  ledger citations; focused test, formatting, and strict clippy passed.
- **2026-08-31** — CLEAN REPRODUCTION. The verify-only native qualification
  then completed two clean Charon/Aeneas runs byte-identically, built all
  3,287 Lean jobs, audited 158 compiled statements, passed all six
  qualification cases, reported four reviewed and zero unreviewed external
  models/axioms, and ended `GO-AENEAS-WITH-PRODUCTION-RESHAPE`. The reviewed
  source-closure digest is now `f1f0812f…28ba`. This removes the capability
  limitation but does not turn Q1 into a pass: the successful command still
  obtained its invocation and mappings from hard-coded xtask constants rather
  than the manifest alone.
- **2026-08-31** — RE-CLOSE. Retained the original question outcomes after
  the intervention: Q1 FAIL, Q2 FAIL, Q3 UNANSWERED, Q4 PASS. Capability is
  now demonstrated rather than assumed, nine divergences are indexed, and the
  subject worktree is clean.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0002-F01 | The algebra invocation is not manifest-only: essential Charon/Aeneas arguments and output mappings remain in xtask constants. | `qualification.toml:219-229`; `xtask/src/formal_qualification.rs:18-91,148-169,1584-1737`. | `adr (#9)`; Q1 fail |
| EXP-0002-F02 | Charon and Aeneas executables were initially unavailable, although their commits and the extraction Rust toolchain were pinned. | Initial native qualification stopped after its lock check. Exact pinned tools were subsequently installed user-wide and their identities recorded. | `bug (fixed operationally)`; capability restored without changing the question |
| EXP-0002-F03 | Algebra currently needs no quarantine, but undeclared template files are not discovered fail-closed because both generated and template inventories are hardcoded lists. | Algebra report: 2 local / 0 external / 0 opaque; no `axiom`, `sorry`, or `admit`; validator paths at `formal_qualification.rs:421-475,1073-1119`. | `adr (#9)`; Q2 fail |
| EXP-0002-F04 | The legacy algebra-linked ledger has six `proved` claims and two `qualified` claims, but those labels do not independently encode theorem, linkage, and assumption facets. | Baseline IDs 018-020 and 025-027; rich IDs 055-056 in `formal/assurance-manifest-v1.toml`. | `adr (#9)`; Q3 unanswered without fresh receipts |
| EXP-0002-F05 | Proofbound's Kani adapter exactly matched all five metadata IDs and rejected an isolated sixth undeclared harness. | Baseline `kani-list.json` SHA-256 `0e22e18b…1f28`; negative diagnostic `PB-KANI-1006`, `missing=[]`, one named extra. | `adr (#9)`; Q4 pass |
| EXP-0002-F06 | The ledger has no standalone claim for either function in the registered two-function Aeneas algebra unit; the only direct crate claims target `threshold_counts`, which is not translated in that unit. | Translation manifest symbols vs claim anchors `:6509`, `:6612`, `:9528`, `:9594`, `:9660`, `:9979`, `:10045`, `:10114`. | `adr (#9)`; inventory mismatch |
| EXP-0002-F07 | Baseline claims 018-020 cite Rust `threshold_counts` but prove properties of handwritten Lean `thresholdTwo`. | `formal/Auths/Composition.lean:20-23,43-52`. | `adr (#9)`; predicted `PROVED / MODEL_ONLY`, attribution must be corrected |
| EXP-0002-F08 | Baseline claims 025-027 use `Generated.thresholdCounts`, but Rust and Lean are parallel products of one generator, not independent source-refinement evidence. | `formal/Auths/Composition.lean:88-114`; generator at `xtask/src/formal.rs:85-245`. | `adr (#9)`; common-origin `MODEL_ONLY` with generator assumption |
| EXP-0002-F09 | Existing statement hashes are hashes of rendered text and cannot be copied into Proofbound's canonical Lean-expression digest field. | Auths hashing at `xtask/src/formal.rs:1237`; Proofbound requires `lean-expr-cbor/1` and `sha256:` domain form. | `adr (#9)`; recomputation required |
| EXP-0002-F10 | The Auths qualification runner did not compile on macOS because it directly compared platform-dependent Unix device-ID integer types. | Rust E0308/E0277 at the two cgroup identity checks; checked-conversion regression, clippy, and full qualification pass at subject commit `ad4f02c`. | `bug (fixed at subject commit ad4f02c)` |
| EXP-0002-F11 | Once capability and portability were repaired, the native pipeline did reproduce byte-identically, but that execution positively confirmed that xtask—not the manifest—remains invocation-authoritative. | Two clean runs; 3,287-job Lean build; 158-statement audit; 6/6 cases; source closure `f1f0812f…28ba`. | `adr (#9)`; Q1 remains fail for manifest inversion |

## Outcome

1. **Q1 — FAIL.** After installing the exact pinned tools and repairing a
   macOS portability defect, two clean translations ran byte-identically.
   They were still driven by hard-coded xtask arguments and mappings, not the
   manifest alone, so the pre-registered criterion remains false.
2. **Q2 — FAIL.** Declared count drift is guarded, but an undeclared template
   file is outside the hardcoded inventory and is not rejected by filesystem
   closure. The algebra's current zero-axiom output does not prove the gate.
3. **Q3 — UNANSWERED.** All eight algebra-linked legacy claims were mapped and
   the status-model disagreements recorded. The native qualification is fresh,
   but no corresponding Proofbound receipts bind those claims and facets, so
   no derived Proofbound facet is claimed.
4. **Q4 — PASS.** Structured Kani metadata produced exactly five registered
   harnesses, and the unchanged manifest rejected a deliberate sixth harness
   bidirectionally with `PB-KANI-1006`.
