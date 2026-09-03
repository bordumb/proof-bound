# Experiment 0023: native Windows enforcement confirmation

- **Status:** preregistered — not executed
- **Registered:** 2026-09-03
- **Subject:** the frozen EXP-0018 effect contract and EXP-0021 Windows policy
- **Operator:** Codex
- **Programme ID:** EXP-LANG-016

## Purpose

EXP-0021 independently compiled the common authority model to a conjunctive
Windows policy but could not execute it. EXP-0023 tests that policy on GitHub's
native `windows-11-arm` hosted runner. A Windows Server runner, compatibility
layer, container, or non-Windows simulation is ineligible.

## Questions

1. **Q1 — Is the registered Windows 11 mechanism available?** Pass only if a
   native ARM64 Windows 11 host creates a fresh AppContainer identity, a
   restricted low-integrity token, a non-breakaway one-process job, and exact
   path access entries before workload entry.
2. **Q2 — Do all 30 permitted workloads complete?** Pass only if the frozen
   Python, Node, and Rust semantic subjects complete ten repetitions each
   beneath the complete conjunctive boundary.
3. **Q3 — Are all 21 authority probes denied without reusable evidence?** Pass
   only if each registered filesystem, environment, process, network, and
   reviewed-write probe reaches its intended operation, is denied, and emits
   no reusable receipt.
4. **Q4 — Do independent Rust and Python validators agree?** Pass only if both
   derive byte-identical reports and reject all 18 registered policy attacks
   exactly.
5. **Q5 — Are Windows-specific premises explicit?** Pass only if the capture
   binds the AppContainer SID, executable and DLL closure, ACLs, token, job,
   normalized paths, reparse-point checks, environment, and before/after tree
   identities.

## Fail-closed constraints

- All four enforcement layers are mandatory; partial setup is unsupported.
- The launcher must assign the suspended process to the job and restricted
  token before user code can run.
- No network capability is granted.
- The runner must reject reparse points and path aliases before ACL changes.
- The reviewed repository is never the execution tree.
- Missing Windows APIs, insufficient privileges, unsupported host identity, or
  cleanup failure emits zero workload receipts and never falls back.

## Decision rule

- **Pass:** supported native Windows 11 execution and Q1–Q5 all pass.
- **Revise:** the mechanism is available, but a bounded enforcement criterion
  fails.
- **Unanswered:** the exact Windows 11 mechanism is unavailable and no
  workload runs.
- **Stop:** any partial or simulated boundary is counted, a denied execution
  becomes reusable, or the reviewed tree changes.

The immutable registration is [preregistration.json](preregistration.json).

