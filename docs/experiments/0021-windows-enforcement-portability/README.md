# Experiment 0021: Windows enforcement portability

- **Status:** planned
- **Registered:** 2026-09-03
- **Started / concluded:** not started / not concluded
- **Subject:** EXP-0018 effect contract at
  `sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d`
- **Proofbound:** `git:2dd8fcd1cb5c6eb76438e00dfb13af20eeb760fc`
- **Operator:** Codex
- **Programme ID:** EXP-LANG-014

## Questions (pre-registered)

1. **Q1 — Can the backend-neutral effect contract compile to a bounded Windows
   policy without changing its meaning?** Pass: every registered effect has
   exactly one explicit Windows disposition and no authority is silently
   ignored or represented only by an authored success flag.
2. **Q2 — Does a real Windows boundary enforce the same project authority?**
   Pass: on Windows arm64 or x86_64 with the registered mechanism available,
   all 30 positive executions complete, all 21 authority probes are denied,
   no denied receipt is reusable, and the reviewed tree is unchanged.
3. **Q3 — Is availability fail-closed?** Pass: absent AppContainer support,
   token/ACL setup failure, job-object failure, architecture mismatch, or a
   non-Windows host yields a typed unsupported result and never a weaker
   substitute.
4. **Q4 — Do independent policy compilers and validators agree?** Pass: Rust
   and Python independently derive byte-identical effective-policy reports and
   reject all registered platform, SID, capability, ACL, job, omission,
   downgrade, alias, and receipt attacks exactly.
5. **Q5 — Is the portability delta explicit and bounded?** Pass: the result
   enumerates AppContainer identity lifecycle, inherited ACLs, runtime/DLL
   reads, process creation, network capability, path normalization, cleanup,
   and all unavoidable differences from macOS and Linux; each implementation
   stays below 1,500 nonblank lines and reports below 192 KiB.

## Scope

- In: Windows 11 arm64 or x86_64; a fresh AppContainer profile and SID;
  explicit path ACL grants; restricted process token; job-object child-process
  control; no network capability; the frozen EXP-0018 corpus.
- Out: Windows Sandbox or containers as substitutes, legacy Windows, GUI
  applications, registry effects beyond explicit denial, production cache
  adoption, and universal NT-object confinement.

## Decision rule

- **Pass:** Q1–Q5 pass on a supported Windows host.
- **Revise:** policy compilation and fail-closed behavior pass, but live
  enforcement or a bounded portability criterion fails.
- **Unanswered:** no supported Windows execution environment is available;
  this must remain visible and cannot be treated as positive evidence.
- **Stop:** unsupported execution falls back, undeclared authority affects
  reusable evidence, or the common contract requires Windows-only semantics.

The immutable machine registration is [preregistration.json](preregistration.json).
