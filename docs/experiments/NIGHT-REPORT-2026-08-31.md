# Overnight experiment report — 2026-08-31

All four pre-registered experiments were started and concluded in order on
the local Proofbound branch `dev-proof-bound-experiment`. Each START pin was
committed before subject work. No remote was pushed, no pull request was
opened, and no artifact was published. Outcomes below are reported per
question; there is deliberately no aggregate score.

## Experiment outcomes

| Experiment | Status | Question outcomes | Divergences | Morning summary |
|---|---|---|---:|---|
| [0001 — Matrix Math release verification](0001-matrix-math-release-verification/README.md) | concluded | Q1 FAIL · Q2 UNANSWERED · Q3 FAIL · Q4 FAIL · Q5 PASS | 5 | The native release verifier is string-search based and repository-local; fresh Lean compilation was unavailable; trusted-transcription evidence could not be materialized honestly; the scoped cost/time question passed. A missing hand-computed omega fixture was restored locally at subject commit `878c0a6`, after which all 20 `mm-cli` tests passed. |
| [0002 — Auths Proof algebra kernel](0002-auths-proof-algebra-kernel/README.md) | concluded | Q1 FAIL · Q2 FAIL · Q3 UNANSWERED · Q4 PASS | 9 | Exact pinned Charon/Aeneas translations ran twice with byte-identical output after a macOS portability repair, but invocation and output ownership remain hard-coded in xtask rather than manifest-authoritative. Structured Kani inventory rejected an undeclared sixth harness. |
| [0003 — semver precedence](0003-semver-precedence/README.md) | concluded | Q1 PASS · Q2 PASS · Q3 UNANSWERED · Q4 PASS | 6 | A useful Tier-0 ledger took 5m25s. Shipping comparison was outside the Aeneas subset; the smallest successful tested pure-kernel extraction was +180/−4 production lines. No refinement theorem was completed. Both registered mutation witnesses failed closed. |
| [0004 — base64 canonical bytes](0004-base64-canonical-bytes/README.md) | concluded | Q1 PASS · Q2 PASS · Q3 FAIL · Q4 PASS | 8 | The corrected Tier-0 board took 25m52s. Four Kani harnesses checked 140,290 registered cases with CaDiCaL and unwind 6, and a negative mutation blocked publication. Pattern A worked mechanically with a kernel digest theorem, but Q3 failed because the corpus was experiment-owned rather than a foreign fixture. |

## Top three findings to read first

1. **Artifact binding can currently overstate what the theorem proves.** In
   the first Experiment 0004 Pattern-A run, checker-authored binding booleans
   produced `ARTIFACT_BOUND` even though the associated audited theorem did
   not mention the artifact digest. The case was rejected and rebuilt around
   one digest-conjoined kernel theorem, but the generic framework hole remains
   open. Read [EXP-0004-D07](DIVERGENCES.md) and
   [ADR 0011](../adr/0011-base64-pilot-receipt-and-binding-boundaries.md).

2. **The subject-native Matrix release path demonstrates the portability and
   parser problem directly.** It extracts manifest values by substring search,
   depends on repository-local state, and cannot serve as an isolated typed
   verifier. This is not merely missing polish; it is the exact trust-boundary
   failure Proofbound is intended to prevent. Read
   [Experiment 0001](0001-matrix-math-release-verification/README.md) and
   [ADR 0008](../adr/0008-experiment-0001-fail-closed-dispositions.md).

3. **Translation reproducibility is not manifest authority.** Auths produced
   two byte-identical pinned translations, but the command vectors, start
   symbols, output mappings, and template inventory still live in xtask
   constants. An undeclared template file is outside the manifest-driven
   closure. Read [EXP-0002-D01 and D02](DIVERGENCES.md) and
   [ADR 0009](../adr/0009-auths-algebra-pilot-dispositions.md).

## Framework changes forced by the night

- Specification 0001 and all package identities advance to **0.6.0**. Bounded
  receipts now retain the registered solver and exact positive per-harness
  unwind map, and bounded status output preserves both the checked property
  and the explicit finite domain.
- Old bounded receipts with empty, partial, extra, mismatched, or zero unwind
  coverage are deliberately no longer admitted.
- Producer and standalone-verifier canonicalization now agree on omitted
  empty `additional_closures`; the release smoke contains real evidence so the
  cross-implementation path remains exercised.
- Four receipt limitations remain explicit for a versioned migration rather
  than a silent `/1` change: model assumptions, unknown versus zero memory,
  separate internal/public statements, and complete ordered command
  provenance.

## Gate and repository integrity

The final Proofbound tree passed the cheap preflight and the complete
clean-snapshot `just ci`. The latter ran all twelve normative stages, executed
one fresh assurance-graph check, released those same receipts, and ended with
the standalone verifier reporting `receipt-consistent` for all 18 registered
project claims with publication admitted. The bootstrap CI commit was created
only inside a disposable repository and is not project-history evidence.

Local subject repairs are isolated on `dev-proof-bound-experiment`: Matrix
fixture repair `878c0a6` and Auths macOS qualification repair `ad4f02c`. The
exact Auths Charon and Aeneas pins were installed under `~/.local` for reuse by
other repositories. No remote action occurred.
