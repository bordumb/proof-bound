# Experiment 0019 journal

- **2026-09-03 — Registration.** Registered the concurrent isolated-process
  candidate before implementation or execution. The 60,000 ms ceiling and all
  EXP-0018 security observations remain unchanged.
- **2026-09-03 — First sandboxed attempt.** The managed tool sandbox denied the
  operator's loopback listener before the candidate ran. This was an outer
  environment denial, not an experiment result. The candidate was rerun with
  the registered host authority needed to create the denial probe.
- **2026-09-03 — Adversarial fixture correction.** The first complete live run
  took 6,245 ms and met every execution invariant, but two generated attack
  fixtures reached `BFX-PARTIAL` and `EFX-COMMAND` before their registered
  duplicate-slot and policy-identity checks. The validators were not relaxed;
  the fixtures were corrected to keep unrelated fields internally coherent.
- **2026-09-03 — Retained execution.** A fresh run completed all 51 distinct
  sandboxes in 6,048 ms. Rust and Python independently emitted the same
  canonical report and rejected all 40 attacks exactly. Decision: `pass`.
