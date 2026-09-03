# Experiment 0025: exact Windows initialization closure

- **Status:** preregistered — not executed
- **Registered:** 2026-09-04
- **Subject:** EXP-0023's retained pre-entry `STATUS_DLL_INIT_FAILED` falsifier
- **Operator:** Codex
- **Programme ID:** EXP-LANG-018

## Purpose

EXP-0023 proved that GitHub's native Windows 11 ARM64 runner exposes the
registered AppContainer, restricted-token, job-object, and ACL APIs. It also
proved that the actual suspended child token and job ordering are correct. A
signed executable staged in AppContainer-owned storage nevertheless terminated
with `STATUS_DLL_INIT_FAILED` before workload entry.

This experiment identifies and binds the minimum Windows process-initialization
closure, then reruns the unchanged EXP-0018 corpus. A green workflow is not a
passing result unless all 30 permitted workloads and all 21 authority probes
actually reach their registered operations.

## Frozen surfaces

The EXP-0018 contract, subjects, arguments, expected output, 30 positive slots,
21 authority probes, non-reuse rule, and semantic authority classes remain
frozen. The following EXP-0023 properties also remain mandatory:

- native `windows-11-arm`, never a container or simulation;
- fresh AppContainer identity with no network capabilities;
- low-integrity token with every present administrator SID deny-only;
- one-process, no-breakaway, kill-on-close job assigned while suspended;
- no user code before token, job, path, environment, and object boundaries;
- fresh copied execution trees and no writes to the reviewed tree; and
- zero reusable evidence for every denied or incomplete execution.

## Candidate change

The only new semantic role is `windows-initialization-closure`. Before the
confirmation run, the instrument must enumerate and identity-bind every
authority needed between `ResumeThread` and workload entry:

1. application executable and recursively required PE images;
2. requested and resolved paths, file IDs, SHA-256, sizes, and ACL grants;
3. AppContainer profile storage and required registry/profile reads;
4. private window-station, desktop, and named-object access;
5. exact platform environment variables separately from declared workload
   variables; and
6. every reparse-point, alias, architecture, or loader-resolution premise.

Discovery may run with tracing authority only to construct a candidate. It
cannot emit reusable evidence. The candidate must then be frozen and tested in
a separate fresh confirmation phase. Confirmation may grant access only to the
registered closure. A dependency observed only after confirmation starts is a
failure, not permission to expand the closure in place.

## Questions

1. **Q1 — Does the exact initialization closure restore entry?** Pass only if
   all three runtimes enter their frozen subjects without enabling an
   administrator SID, raising integrity, removing AppContainer, weakening the
   job, or using a shared mutable execution root.
2. **Q2 — Do all 30 permitted workloads complete?** Pass only if ten Python,
   ten Node, and ten Rust executions produce the exact frozen output.
3. **Q3 — Are all 21 authority probes denied and non-reusable?** Pass only if
   every registered filesystem, environment, process, network, and reviewed-
   write probe reaches its intended operation, is denied, and emits no reusable
   receipt.
4. **Q4 — Is the initialization closure exact?** Pass only if omission,
   substitution, alias, reparse point, digest, size, file-ID, ACL, environment,
   token, job, profile, object, and broad-directory-grant attacks are rejected
   with exact classifications.
5. **Q5 — Do independent validators agree?** Pass only if Rust and Python
   produce byte-identical reports, reject every registered attack, bind the
   before/after tree identities, and confirm zero fallback and zero denied
   reuse.

## Decision rule

- **Pass:** Q1–Q5 pass on native Windows 11 ARM64.
- **Revise:** a bounded initialization candidate executes but any registered
  workload, denial, exactness, or validation criterion fails.
- **Unanswered:** the eligible native mechanism or required diagnostic surface
  is unavailable and zero workload receipts are emitted.
- **Stop:** any sandbox layer is removed or weakened, a discovery execution is
  counted as evidence, authority broadens after confirmation begins, denied
  evidence becomes reusable, or execution falls back.

The immutable registration is [preregistration.json](preregistration.json).
