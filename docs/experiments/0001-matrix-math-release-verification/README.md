# Experiment 0001: Matrix Math release verification (publish repo)

- **Status:** running
- **Registered:** 2026-08-31 (re-registered same day against the publish
  repo; see journal)
- **Started / concluded:** 2026-08-31 / —
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

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| — | — | — | — |

## Outcome

Not yet run.
