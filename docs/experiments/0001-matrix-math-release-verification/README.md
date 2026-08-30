# Experiment 0001: Matrix Math release verification

- **Status:** planned
- **Registered:** 2026-08-31
- **Started / concluded:** — / —
- **Subject:** local `matrix-math` repository at commit
  `fb7afc70b27bbbf5c3cb8fde61e9d9acb482501d`, canonical source digest
  `7c47b198db3e279bf21f3839c877a851fefd23e475c4277f7dcd93dc22719048`
  (no remote — see Q4)
- **Proofbound:** `90a117e` at registration; re-pin at start after the
  bootstrap commit lands
- **Operator:** TBD-at-start

## Why this first

Matrix Math's release verification is its weakest subsystem: the verifier
parses its release manifest by substring search (prohibited by Specification
0001 §18.2), the CI assurance gate is stale against the active manifest, and
publication artifacts are untracked local state. Replacing it with
`proofbound release` + `proofbound-verify` is an upgrade to the subject, not
just a test of the framework — and it exercises Pattern A at real scale,
including the known digest-binding gap (only 2 of 20 committed ω modules use
digest-conjoined theorems).

## Questions (pre-registered)

1. **Q1 — Independent release verification.** Can a third party verify a
   Matrix Math release holding only the release directory and the
   `proofbound-verify` binary, with structured parsing throughout? Pass: the
   verifier reports receipt-consistent on a clean machine with no
   string-search field extraction anywhere in the path.
2. **Q2 — Artifact soundness without core changes.** Can at least one ω
   claim be registered as `artifact-soundness` with binding `digest-theorem`
   using only manifests and the existing generated module machinery? Pass:
   the claim compiles into the assurance graph as `ARTIFACT_BOUND` with the
   `native` evaluation mode visible.
3. **Q3 — Trusted transcription classifies Track B honestly.** Can a rank
   claim be registered as `trusted-transcription` with the Rust round-trip
   re-encoder in the TCB inventory, rendering `TRANSCRIBED` (never
   `ARTIFACT_BOUND`)? Pass: the report shows the honest facet and the
   `artifact-bound` profile rejects the claim.
4. **Q4 — Sealing the no-remote caveat.** Can the audited source closure be
   sealed into Proofbound's CAS so the Specification 0001 §15 local-only
   caveat is discharged? Pass: a durable content-addressed archive exists and
   its digest is added to the §15 record.
5. **Q5 — Migration cost.** What does the bounded subset cost? Pass: hours
   and divergence count recorded in the journal, whatever they are.

## Scope

- In: release verification path; one ω (CN) claim and one rank claim;
  closure sealing.
- Out: the remaining ~30 claims; campaign/experiment machinery; the Python
  optimizer; fixing Matrix Math's stale CI beyond the verified-release path.

## Journal (append-only)

- **2026-08-31** — Pre-registered. Not started.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| — | — | — | — |

## Outcome

Not yet run.
