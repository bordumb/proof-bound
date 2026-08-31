# Experiment 0001: Matrix Math release verification (publish repo)

- **Status:** concluded
- **Registered:** 2026-08-31 (re-registered same day against the publish
  repo; see journal)
- **Started / concluded:** 2026-08-31 / 2026-08-31
- **Subject:** `matrix-math-publish` at commit
  `3794e68b9dfeeae2b7d6d7d3c29bf512530a5b09`
  (github.com/bsd-developer/matrix-math-publish; local checkout at
  `other_repos/matrix-math-publish`); deterministic `git archive` SHA-256
  `6f2003904ecc12cd1056f0c2ffcf6ab70abd879720022bee2ea3f9c02454a845`
- **Proofbound:** `926f5eab41a20aaca7a1a892ac83181f5bd34247`
- **Operator:** Codex (GPT-5)

## Why this subject

The private `matrix-math` repository contains competitive optimization-search
work and is not publishable. The publish repo carries exactly the parts a
verifier needs: the certification core (Lean decoder, soundness theorems,
compiled axiom audit, 29 registered claims), 38 committed generated modules
(19 ω Track A, 19 rank Track B), a committed ω certificate artifact, the
`mm-cli` verify/prove/verify-release path, and a real remote.

That split is not a compromise — it is Pattern A's own thesis made concrete:
the untrusted producer is not needed to verify what it produced. This
experiment therefore tests both the release-verification replacement *and*
whether Proofbound can state the producer-absent boundary honestly. It also
inherits the private repo's known weaknesses worth fixing: substring-search
release verification (prohibited by Specification 0001 §18.2) and the
digest-binding gap (a minority of ω modules use digest-conjoined theorems).

The private repository stays out of every closure, receipt, and claim. The
§15 reference audit of the private repo (commit `fb7afc7…`) remains valid as
a historical record; this experiment binds only the publish repo.

## Questions (pre-registered)

1. **Q1 — Independent release verification.** Can a third party verify a
   matrix-math-publish release holding only the release directory and the
   `proofbound-verify` binary, with structured parsing throughout? Pass: the
   verifier reports receipt-consistent on a clean machine, with no
   string-search field extraction anywhere in the path.
2. **Q2 — Artifact soundness without core changes.** Can at least one ω
   claim (from the committed certificate artifact) be registered as
   `artifact-soundness` with binding `digest-theorem`, using only manifests?
   Pass: the claim compiles into the assurance graph as `ARTIFACT_BOUND`
   with the `native` evaluation mode visible at the evidence level.
3. **Q3 — Trusted transcription classifies Track B honestly.** Can a rank
   claim (a `Cert_*` module) be registered as `trusted-transcription` with
   the Rust round-trip re-encoder in the TCB inventory, rendering
   `TRANSCRIBED` and rejected by the `artifact-bound` profile? Pass: the
   report shows the honest facet with no core forks.
4. **Q4 — The producer-absent boundary is a claim, not a caveat.** With the
   optimization campaign private, do all registered claims still verify, and
   is certificate *provenance* expressed as an explicit assumption or
   out-of-scope entry rather than silently absorbed? Pass: the board
   renders with no claim citing evidence it lacks, and the private search
   appears in no semantic closure, receipt, or TCB entry.
5. **Q5 — Migration cost.** What does the bounded subset cost? Pass: hours
   and divergence count recorded in the journal, whatever they are.

## Scope

- In: the publish repo's release-verification path; one ω (CN) claim and one
  rank claim; the producer-absent boundary claims.
- Out: the private `matrix-math` repository entirely; the remaining ~27
  registered claims; the `paper/` directory's prose claims; rebuilding the
  publish repo's trimmed CI beyond the verified-release path.

## Journal (append-only)

- **2026-08-31** — Pre-registered against the private `matrix-math`
  repository (commit `fb7afc70b27bbbf5c3cb8fde61e9d9acb482501d`, source
  digest `7c47b198…9048`).
- **2026-08-31** — Re-registered against `matrix-math-publish` before any
  experiment work began: the private repo is competitive work and will not
  be published. Questions rewritten; the former CAS-sealing question is
  obsolete (the publish repo has a public remote) and is replaced by the
  producer-absent boundary question (Q4). No experiment work had started,
  so this replacement is a legal pre-registration edit.
- **2026-08-31** — START. Pinned the clean publish checkout to commit
  `3794e68b9dfeeae2b7d6d7d3c29bf512530a5b09`, deterministic Git-archive
  SHA-256 `6f2003904ecc12cd1056f0c2ffcf6ab70abd879720022bee2ea3f9c02454a845`,
  and Proofbound commit `926f5eab41a20aaca7a1a892ac83181f5bd34247`.
- **2026-08-31** — CHEAP BASELINE. The committed omega artifact reproduced
  byte digest `55148017090a8883ab18bbd1316196fadc32b2f5f41cbf751d838d5c334f895f`
  and passed the Rust check, but the subject reported `XC`: no Lean theorem
  was built. The focused round-trip tests passed 4/4; the full `mm-cli` test
  target failed 4/20 because the publish snapshot omits
  `tests/vectors/omega-l2-hand.json`.
- **2026-08-31** — CAPABILITY. Lean and Lake are installed, but the pinned
  Mathlib checkout is absent. Lake attempted to fetch it and failed DNS. Per
  the experiment rules no toolchain was installed, and the affected formal
  question was left unanswered.
- **2026-08-31** — TIER 0. `proofbound init` produced a working overlay in an
  isolated Git snapshot on branch `dev-proof-bound-experiment`. The first
  selected omega test honestly failed because its untracked fixture was not
  in the pinned archive. A self-contained exact-byte `CompareWriter` test was
  then registered and produced `TESTED / MODEL_ONLY`, policy admitted, with
  its assumption and not-proved section visible.
- **2026-08-31** — RELEASE. External adoption required copying the 22 pinned
  v0.5 public schema files into the subject snapshot. Proofbound then emitted
  a clean portable release, but a separately copied `proofbound-verify` binary
  rejected it with `PBV_NON_CANONICAL`. Typed reserialization showed the
  producer emitted empty `additional_closures` and `generated_artifacts` in
  wire shapes the verifier canonicalizes differently. Q1 therefore failed;
  the verifier was not bypassed and the product was not patched mid-pilot.
- **2026-08-31** — CLOSE. Applied the questions literally. In particular, Q4
  was not stretched into a pass: the required out-of-scope disclosure itself
  necessarily appears in the receipt, while the pass sentence says the
  private search appears in no receipt. Elapsed operator wall time was about
  0.25 hours. Five divergences are indexed in the shared ledger and disposed
  by ADR 0008.
- **2026-08-31** — POST-CONCLUSION REPAIR. At the operator's direction, the
  omitted hand-computed omega fixture was recovered from the private reference
  repository only after a provenance and sensitivity audit. The exact
  10,051-byte blob (`6e2cc34a…ea2d`, SHA-256 `00ccbe73…e2d`) was committed as
  the sole change on the subject's local `dev-proof-bound-experiment` branch
  at `878c0a660a7df966d4ca5de574b1587247bb4871`. The formerly red `mm-cli`
  target then passed 20/20; schema round-trip, exact evaluator, symmetric
  domain, and native CLI verification checks also passed. Nothing was pushed
  or published. This repairs F05 but does not retroactively change the
  pre-registered Q1–Q5 outcomes.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0001-F01 | The native `mm verify-release` path uses substring field extraction, requires the repository-local CAS, and has no committed release/CAS payload at the pin. | `crates/mm-cli/src/report.rs:240-312`; no tracked `docs/results/**` or `data/cas/**`; `mm report` rejected the omega artifact as `unknown_field l_star`. | `adr (#8)`; Q1 fail |
| EXP-0001-F02 | Proofbound's structured release producer and independent verifier disagree on the compiled-receipt wire shape for empty provenance collections. | Release at local test pin `f7c8076…`; isolated verifier returned `PBV_NON_CANONICAL`; typed canonicalization changed 25,103 bytes to 25,053 bytes, first divergence at empty `additional_closures` / `generated_artifacts`. | `adr (#8)`; product bug left fail-closed |
| EXP-0001-F03 | The committed omega module has the requested digest-theorem/native source shape, but the theorem could not be freshly compiled or audited. | Artifact SHA-256 `55148017…895f`; generated module SHA-256 `c83bc7da…9376`; `.lake/packages` empty and pinned Mathlib unavailable. | `accepted-limitation`; Q2 unanswered |
| EXP-0001-F04 | The selected rank module is a typed transcription, but the original certificate is absent and v0.5 has no adapter path that materializes `trusted-transcription` plus the transcriber/re-encoder TCB nodes. | `Cert_c5bb171443bb54f0.lean` SHA-256 `6b1d2ace…1fb5`; historical digest `c5bb1714…2f0b`; focused Rust round-trip tests 4/4; only the omega certificate is tracked. | `adr (#8)`; Q3 fail, no core fork |
| EXP-0001-F05 | The publish snapshot's `mm-cli` tests were not clean-checkout reproducible: four omega generator tests referenced an omitted fixture. | Baseline: 16 passed, 4 failed. Exact fixture restored from audited blob `6e2cc34a…ea2d`; repaired branch: 20/20 plus all focused checks green. | `bug (fixed at subject commit 878c0a6)`; original baseline retained |
| EXP-0001-F06 | The private campaign revision/path is absent, but `mm-cli` still compiles the public `mm-search` producer and Q4's literal receipt wording contradicts its required explicit exclusion. | `mm-cli` normal dependency on `mm-search`; structured Tier-0 receipt includes the registered exclusion and no private repository identity. | `adr (#8)`; Q4 fail under literal criterion |
| EXP-0001-F07 | The bounded Tier-0 overlay cost about 0.25 wall-clock hours and three local subject commits after the synthetic snapshot: generated ledger, exact test binding, and 22 vendored schemas. | Two successful fresh checks took 18.7s and 17.3s; final status `TESTED / MODEL_ONLY`; five ledgered divergences. | `case-record`; Q5 pass |

## Outcome

1. **Q1 — FAIL.** The native path is string-search/local-CAS based. The
   replacement path used structured parsing, but its emitted release was
   rejected by the independent verifier as non-canonical. A release that its
   independent verifier rejects does not pass.
2. **Q2 — UNANSWERED.** Static inspection found the correct
   `digest-theorem` and `native_decide` shape, but the pinned Mathlib dependency
   was unavailable, so no fresh compiled theorem or axiom audit exists.
3. **Q3 — FAIL.** The subject is clearly trusted transcription, but the exact
   source artifact is absent and Proofbound v0.5 cannot materialize that
   evidence/TCB shape without framework work. No core fork was made.
4. **Q4 — FAIL.** The bounded Tier-0 claim verified and disclosed the producer
   exclusion, and no private-repository identity entered the closure or TCB.
   The literal pass criterion is nevertheless false: that disclosure appears
   in the receipt, and the public `mm-search` producer remains in the binary's
   build closure.
5. **Q5 — PASS.** About 0.25 operator wall-clock hours and five divergences
   were recorded. No aggregate score is reported.
