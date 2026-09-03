# Experiment 0020 journal

- **2026-09-03 — Registration.** Registered Linux arm64/x86_64, Landlock ABI
  4, `no_new_privs`, seccomp network denial, the inherited 51 live operations,
  and an explicit `unanswered` outcome before implementation or probing.
- **2026-09-03 — Environment construction.** Built the launcher in a
  digest-pinned Debian Bookworm/Python image. The large initial image download
  was setup cost and is not included as enforcement evidence.
- **2026-09-03 — Live mechanism probe.** Docker Desktop supplied Linux arm64
  kernel `6.12.54-linuxkit`, but `landlock_create_ruleset` returned `ENOSYS`.
  Disabling Docker's outer seccomp profile did not change the result.
- **2026-09-03 — Fail-closed capture.** Retained a typed unsupported capture
  with zero workload slots. The executor did not run under a weaker boundary
  and did not count the container as enforcement.
- **2026-09-03 — Independent validation.** Rust and Python emitted identical
  reports, compiled all nine authority classes, and rejected all 16 registered
  attacks exactly. Decision: `unanswered`.
