# Experiment 0020: Linux enforcement portability

- **Status:** concluded — unanswered
- **Registered:** 2026-09-03
- **Started / concluded:** 2026-09-03 / 2026-09-03
- **Subject:** EXP-0018 effect contract at
  `sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d`
- **Proofbound:** `git:2dd8fcd1cb5c6eb76438e00dfb13af20eeb760fc`
- **Operator:** Codex
- **Programme ID:** EXP-LANG-013

## Questions (pre-registered)

1. **Q1 — Can the backend-neutral effect contract compile to a bounded Linux
   policy without changing its meaning?** Pass: every registered read,
   absence, permission, environment, executable, ephemeral-write,
   reviewed-write-denial, and network-denial effect has exactly one explicit
   Linux disposition, with no silently unhandled authority.
2. **Q2 — Does a real Linux boundary enforce the same project authority?**
   Pass: on Linux with the registered mechanism available, all 30 positive
   executions complete, all 21 authority probes are denied, no denied receipt
   is reusable, and the reviewed tree is unchanged.
3. **Q3 — Is availability fail-closed?** Pass: missing kernel features,
   insufficient Landlock ABI, missing seccomp support, architecture mismatch,
   or execution on a non-Linux host yields a typed unsupported result and
   never an observed or reusable substitute.
4. **Q4 — Do independent policy compilers and validators agree?** Pass: Rust
   and Python independently derive byte-identical canonical effective-policy
   and validation reports and reject all registered policy, platform,
   mechanism, omission, downgrade, and receipt attacks exactly.
5. **Q5 — Is the portability delta explicit and bounded?** Pass: the result
   enumerates Linux system-read roots, dynamic-loader premises, kernel ABI,
   filesystem semantics, and all unavoidable differences from macOS; each
   implementation stays below 1,400 nonblank lines and reports below 192 KiB.

## Scope

- In: Linux x86_64 or arm64; Landlock filesystem/execute restriction;
  `no_new_privs`; seccomp denial of networking; the frozen EXP-0018 corpus.
- Out: containers as proof of host confinement, privileged namespaces,
  distribution packaging, other architectures, Windows, production cache
  adoption, and universal syscall completeness.

## Decision rule

- **Pass:** Q1–Q5 pass on a supported Linux host.
- **Revise:** policy compilation and fail-closed behavior pass, but live
  enforcement or a bounded portability criterion fails.
- **Unanswered:** no supported Linux execution environment is available; this
  must not be converted into a positive result.
- **Stop:** unsupported execution falls back, undeclared authority affects
  reusable evidence, or the common contract requires Linux-only semantics.

The immutable machine registration is [preregistration.json](preregistration.json).
The retained outcome is documented in [CONCLUSION.md](CONCLUSION.md); its
machine evidence is indexed by [ARTIFACTS.md](ARTIFACTS.md).
