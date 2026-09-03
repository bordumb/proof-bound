# Experiment 0022 journal

- **2026-09-03 — Registration.** Frozen the EXP-0020 contract, Dockerfile,
  launcher, runner, independent validators, 30 positive slots, 21 authority
  probes, and 16 validation attacks before probing a supported host.
- **2026-09-03 — Docker Desktop qualification.** Rebuilt the exact registered
  image. Both the default Docker profile and `seccomp=unconfined` returned
  `ENOSYS` to the Landlock ABI query. No workload ran and this environment did
  not count as Linux enforcement evidence.
- **2026-09-03 — Native Linux execution.** GitHub run
  `33809008381` used a native Ubuntu 24.04 ARM64 runner. The launcher reported
  Linux kernel `6.17.0-1022-azure` and Landlock ABI 7, then executed all 51
  frozen slots in 1,257 ms.
- **2026-09-03 — Confirmatory failure.** Every positive and authority slot was
  denied at `exec` with `runtime-exec: Permission denied`. Rust and Python
  independently classified the capture `LNX-POSITIVE-OUTCOME`. Decision:
  `revise`.

