# Experiment 0022: native Linux enforcement confirmation

- **Status:** concluded — revise
- **Registered:** 2026-09-03
- **Started / concluded:** 2026-09-03 / 2026-09-03
- **Subject:** the frozen EXP-0020 Linux corpus and implementation
- **Operator:** Codex
- **Programme ID:** EXP-LANG-015

## Purpose

EXP-0020 compiled the common effect contract to Landlock, `no_new_privs`, and
seccomp, but its available Docker Desktop Linux VM returned `ENOSYS` to the
Landlock ABI query. This confirmatory experiment repeats the exact frozen
EXP-0020 workload on a Linux environment that reports Landlock ABI 4 or newer.

Docker or another VM may transport the workload to a Linux kernel. Container
confinement is not evidence for this experiment: only the registered native
launcher and its independently checked receipts count.

## Frozen inputs

The following EXP-0020 inputs are reused byte-for-byte:

- the EXP-0018 effect contract;
- the digest-pinned Dockerfile and native C launcher;
- the Python execution harness;
- the independent Rust and Python policy validators;
- 30 permitted executions across Python, Node, and Rust;
- 21 authority probes; and
- 16 retained validation attacks.

Their exact identities are recorded in
[preregistration.json](preregistration.json). Changing any frozen input makes
this experiment ineligible rather than creating a revised positive result.

## Questions

1. **Q1 — Is the native Linux mechanism available?** Pass only if the exact
   launcher reports Linux on arm64 or x86_64, Landlock ABI 4 or newer, and can
   install both `no_new_privs` and its registered seccomp filter.
2. **Q2 — Do all permitted workloads complete?** Pass only if all 30 frozen
   positive executions complete beneath the registered native boundary.
3. **Q3 — Are all forbidden authorities denied without reusable evidence?**
   Pass only if all 21 frozen probes are denied, every denial has its exact
   registered classification, and no denied execution is reusable.
4. **Q4 — Is the result independently reproducible?** Pass only if the Rust
   and Python validators emit byte-identical reports and reject all 16 attacks
   exactly.
5. **Q5 — Is the reviewed subject unchanged?** Pass only if the before and
   after tree identities are equal and container confinement is not counted.

## Corrected availability rule

EXP-0020's prose correctly required unsupported environments to fail closed,
but its final evaluator encoded Q3 as true only when the host was unsupported.
That made a supported execution mathematically unable to reach `pass`.

EXP-0022 corrects only that decision defect: availability handling passes when
either the registered mechanism is supported and the full corpus runs, or the
mechanism is unsupported and zero workload receipts are emitted. A positive
EXP-0022 decision still requires supported availability and Q1–Q5.

## Decision rule

- **Pass:** supported availability and Q1–Q5 all pass.
- **Revise:** the mechanism is supported, but any workload, denial,
  independence, or immutability criterion fails.
- **Unanswered:** the exact host probe is unsupported and emits zero workload
  receipts without fallback.
- **Stop:** the runner falls back to container confinement or an unconfined
  execution, or any denied execution becomes reusable.

The retained outcome is documented in [CONCLUSION.md](CONCLUSION.md), and its
machine evidence is indexed by [ARTIFACTS.md](ARTIFACTS.md).

