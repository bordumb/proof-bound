# Experiment 0002: Auths Proof algebra kernel

- **Status:** planned
- **Registered:** 2026-08-31
- **Started / concluded:** — / —
- **Subject:** `auths-proof` repository at commit
  `95c9d4583e10fdc3ffaecc0a96790bec1c922640` (branch
  `codex/formal-source-closure`), translation source-closure digest
  `616fcfae33e76019a1e9c59dfc886375b8e2f92dbf381fb2074a7df7bfa5f741`
- **Proofbound:** `90a117e` at registration; re-pin at start after the
  bootstrap commit lands
- **Operator:** TBD-at-start

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

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| — | — | — | — |

## Outcome

Not yet run.
