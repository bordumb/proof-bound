# First-hour experience

[Documentation map](../README.md) · [Working notes](README.md)

- **Status:** active
- **Created:** 2026-09-01
- **Last updated:** 2026-09-01
- **Purpose:** An actionable, ranked plan for the fixes that gate a
  stranger's first hour with Proofbound, with per-item acceptance
  criteria and the existing normative obligations each item satisfies.

## Summary

Five defects end a new user's evaluation before the product's value is
visible, in a strict kill-order: no way to install the binary; a second
required binary nobody documents; adapter failures that render as a bare
`INVALID` with no cause; an untracked `.proofbound/` directory that
makes every project permanently dirty; and a status/error surface that
refuses to render or to name the offending file. All five are CLI- and
packaging-layer work. The trust kernel needs no changes. Three of the
five are not new design at all — they implement behavior Specification
0001 already mandates (§12.2, §12.3).

**Definition of done for the whole note** (the product vision's own
Phase 2 target): a person who has never seen this repository reaches an
honest Tier 0 claim board on their own machine, from the public install
instruction, in fifteen minutes — and when something fails, the failure
names its cause and its file.

## Context

Every item below was verified, not hypothesized:

- The stranger's journey and its four cliffs are documented in
  [Product analysis §4](../product-analysis.md); the compact fix list is
  its §8 item 1.
- Experiments 0003 and 0004 measured the good path (5m25s and 25m52s to
  a Tier 0 board) and hit the `.proofbound/` dirty-tree cliff in the
  field (`docs/experiments/0003-semver-precedence/`).
- The error-localization failure was reproduced live on this branch:
  three consecutive `PB-CHECK-0001` refusals that were *correct*
  (concurrent edits during the run) while naming no file — the operator
  needed a manual before/after content-hash inventory to learn what the
  tool already knew.
- [Product vision, Phase 2](../product-vision.md) states the goal but
  none of the fixes; this note is the missing plan.

## Work items

Ranked by kill-order: each item ends the evaluation before the next is
reached. Effort assumes the demonstrated repo pace.

### F1. Publish an installable release (~1 day)

- **Problem.** Nothing is published. The workspace manifest's
  repository URL is the placeholder `https://example.invalid/proofbound`
  (`Cargo.toml`). `README.md` says "install the `proofbound` binary"
  with no command, and its quickstart is a *contributor* bootstrap
  requiring Rust, `uv`, and a Lean toolchain — contradicting the
  product's own no-Lean-for-the-first-result principle
  ([product vision](../product-vision.md), adoption principles).
- **Fix.** Cut a versioned GitHub release with prebuilt binaries for
  macOS and Linux (cargo-dist or equivalent); set the real repository
  URL; put the user install command and a five-line `init → check →
  status` quickstart at the top of `README.md`, above the contributor
  section.
- **Acceptance.** On a machine with no Rust, `uv`, or Lean: install
  from the public instruction, run `proofbound --version`, and reach
  `init` on a scratch repository.

### F2. Ship the adapter binaries with the CLI (~1–2 days)

- **Problem.** Tier 0 evidence executes through the separate
  `proofbound-adapter-test` binary (resolution order:
  `PROOFBOUND_ADAPTER_DIR`, then the CLI's sibling directory, then
  `PATH` — `crates/proofbound-cli/src/adapter.rs`). No document
  mentions this. Installing only `proofbound` yields a red board.
- **Fix.** Include all adapter executables in the F1 release archive as
  siblings of `proofbound`, so the existing sibling-directory
  resolution finds them with zero configuration. Document
  `PROOFBOUND_ADAPTER_DIR` and the resolution order in the README and
  in `doctor` output.
- **Acceptance.** The F1 install, with no environment configuration,
  runs a Tier 0 `check` whose evidence units execute; `doctor` lists
  each adapter binary and its resolved path.

### F3. Render unit diagnostics in reports (~1 day)

- **Problem.** When an adapter cannot start, the failure is captured as
  `PB-ADAPTER-0900` with correct remediation text in the compiled
  state's `unit_runs[].diagnostics` — which no human report and no
  `--json` projection renders (`crates/proofbound-cli/src/report.rs`
  reads `unit_runs` only for freshness). The user sees
  `INVALID / BLOCKED` with no cause.
- **Fix.** Render per-unit diagnostics (code, message, remediation)
  beneath the `status` board and in `claim`/`explain` output, and add
  them to the JSON projections.
- **Acceptance.** Deleting the adapter binary and running `check` +
  `status` shows the `PB-ADAPTER-0900` remediation on the board itself;
  a test pins the rendering.

### F4. `init` owns the `.proofbound/` ignore rule (~half a day)

- **Problem.** Tree state is computed with `--untracked-files=all`
  (`crates/proofbound-evidence/src/provenance.rs`), so after the first
  `check` every project is permanently `dirty`, silently blocking
  `release` and `update`. Experiment 0003 hit this and hand-fixed it.
- **Fix.** `init` appends `.proofbound/` to the repository's
  `.gitignore` (creating it if absent), or — where it cannot write the
  rule — says so in its output with the exact line to add.
  Specification 0002 §11.2 already states this as a MUST for the Python
  path; implement it for every `init` path.
- **Acceptance.** `init && check` on a fresh repository leaves
  `git status` clean and the board's tree state `clean`; `release` is
  reachable without manual ignore-file surgery.

### F5. Degrade `status`; localize errors (~2–3 days)

- **Problem A.** After any file edit, bare `status` fails with
  `PB-RECEIPT-0007: compiled result is stale` instead of rendering —
  the observability surface's default state is an error message
  followed by a multi-minute re-check.
- **Problem B.** The `proofbound-error/1` envelope's localization
  fields (`file`, `expected_identity`, `actual_identity`, `claim_id`,
  `affected_claims`) are unconditionally null/empty
  (`crates/proofbound-cli/src/main.rs`), although Specification 0001
  §12.3 requires them when applicable. `PB-CHECK-0001` is the worst
  case: the check compares two worktree snapshots, so it *knows* the
  changed paths, and reports none of them.
- **Fix.** (a) `status` renders the last valid board marked
  prominently STALE with the exact reason, and exits nonzero — degrade,
  don't refuse. (b) Thread structured error context to the envelope:
  at minimum, `PB-CHECK-0001` lists the changed paths, and
  identity-mismatch errors carry expected/actual digests. This is 0001
  §12.3 conformance work, not new design.
- **Acceptance.** Editing a file after `check` still shows the (stale)
  board; a concurrent-edit `PB-CHECK-0001` names every changed path;
  the JSON envelope for an identity mismatch carries both digests.

## Follow-on items (not first-hour-fatal)

1. Add the missing assumption-facet column to the `status` table — the
   spec's three-facet board (0001 §6.3.1) currently renders two.
2. Add the cache-vs-fresh field to `status --json` — a 0001 §12.2
   requirement present only in human output.
3. Write the fifteen-minute quickstart guide in `docs/guides/`,
   replacing the accidental onboarding role of the experiment journals.

## Sequencing

F1 → F2 → F3 → F4 → F5, roughly one focused week total. F1/F2 are one
packaging change and should land together. This plan precedes the
ecosystem specs in priority: Specifications 0002 and 0003 widen the
funnel, but every route they add sits behind this same front door, and
their reference verticals (0002 M-PY5, 0003 M-TS5) assume an installable
product to be demonstrations at all.

## Promotion criteria

- F3, F5, and the follow-on items change normative CLI behavior:
  promote their final shapes into a Specification 0001 revision (§12.2
  reporting, §12.3 error contract) when implemented, per this
  directory's lifecycle rules.
- F1/F2's release layout (bundled adapters, resolution order) belongs
  in an ADR once accepted.
- Mark this note `promoted` when the definition-of-done demonstration —
  a fifteen-minute stranger run on a fresh machine — is recorded as an
  experiment under `docs/experiments/`.
