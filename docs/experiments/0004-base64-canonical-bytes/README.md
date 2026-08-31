# Experiment 0004: base64 canonical bytes

- **Status:** running
- **Registered:** 2026-08-31
- **Started / concluded:** 2026-08-31 / —
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

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| — | — | — | — |

## Outcome

Not yet run.
