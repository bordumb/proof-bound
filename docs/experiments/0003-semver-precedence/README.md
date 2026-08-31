# Experiment 0003: semver precedence

- **Status:** running
- **Registered:** 2026-08-31
- **Started / concluded:** 2026-08-31 / —
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

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| — | — | — | — |

## Outcome

Not yet run.
