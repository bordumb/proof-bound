# Experiment 0019: Batched enforcement latency

- **Status:** concluded; pass
- **Registered:** 2026-09-03
- **Started / concluded:** 2026-09-03 / 2026-09-03
- **Subject:** EXP-0018 frozen corpus at
  `sha256:9686074a5cd8e5f2b3f0018ab95104f697bce292e0e948482220ec378780bd43`
- **Proofbound:** `git:2dd8fcd1cb5c6eb76438e00dfb13af20eeb760fc`
- **Operator:** Codex
- **Programme ID:** EXP-LANG-012

## Questions (pre-registered)

1. **Q1 — Can concurrent scheduling repair the frozen latency failure without
   weakening isolation?** Pass: one complete capture retains all 30 positive
   executions and all 21 denied authority probes as separately identified
   process receipts, with zero denied reusable receipts, an unchanged reviewed
   tree, and total wall time at or below the original 60,000 ms ceiling.
2. **Q2 — Are batch membership and per-run authority unambiguous?** Pass: every
   registered slot occurs exactly once, owns a distinct ephemeral root, binds
   one plan and receipt identity, and all registered omission, duplication,
   reordering, swapping, aliasing, partial-result, policy, and outcome attacks
   reject with their exact registered codes.
3. **Q3 — Does batching preserve the EXP-0018 assurance result?** Pass: the
   original 30 semantic attacks and ten new scheduler attacks reject exactly,
   registered dependency changes invalidate, and the unrelated control does
   not invalidate any positive slot.
4. **Q4 — Can independent implementations validate the batched result?** Pass:
   Rust and Python validators independently derive byte-identical canonical
   reports from the retained capture without trusting child-authored reuse or
   outcome fields.
5. **Q5 — Is the candidate bounded enough to retain?** Pass: the scheduler and
   Rust validator stay below 1,600 nonblank lines, the independent Python
   validator below 1,000, each generated policy below 160 lines, and the
   canonical report below 192 KiB.

## Scope

- In: macOS arm64 Seatbelt; concurrent scheduling of independently sandboxed
  processes; the exact EXP-0018 subjects, positive count, authority probes,
  effect vocabulary, and 60-second ceiling.
- Out: long-lived language runtimes, shared sandbox processes, Linux, Windows,
  production cache adoption, syscall-complete hermeticity, and explanations of
  performance beyond the registered measurements.

## Decision rule

- **Pass:** Q1–Q5 pass.
- **Revise:** every security and independent-validation criterion passes but a
  bounded performance or complexity criterion fails.
- **Stop:** batching permits stale reuse, cross-slot confusion, ambient
  authority, silent fallback, or a denied execution to become reusable.

The immutable machine registration is [preregistration.json](preregistration.json).
Execution observations will be appended to [JOURNAL.md](JOURNAL.md).

## Outcome

The experiment **passes**. The complete 51-process corpus finished in 6,048 ms,
compared with the immutable 93,574 ms baseline and 60,000 ms ceiling. Every
process retained its own plan, policy, ephemeral root, raw outcome, and receipt;
no enforcement process or authority was shared.

- **Q1: pass.** Thirty positive runs and 21 denied probes completed in 6,048 ms;
  no denial was reusable and the reviewed tree was unchanged.
- **Q2: pass.** All 51 roots were unique, all 30 positive outputs were unique,
  and all ten scheduler attacks rejected exactly.
- **Q3: pass.** All 30 EXP-0018 attacks still rejected exactly; stale reuse and
  unrelated invalidation remained zero.
- **Q4: pass.** Rust and Python emitted byte-identical 10,249-byte reports.
- **Q5: pass.** Rust used 1,083 nonblank lines, Python 401, policies at most 31,
  and the report remained below every frozen ceiling.

The performance result is a scheduler result, not evidence that sharing a
long-lived sandbox is safe. Production may schedule isolated executions
concurrently, but must continue to retain and validate each run separately.

See [CONCLUSION.md](CONCLUSION.md) and the retained [results](results/README.md).
