# Experiment 0024: exact Linux loader execution closure

- **Status:** concluded — pass
- **Registered:** 2026-09-03
- **Subject:** EXP-0022's retained runtime-execution falsifier
- **Operator:** Codex
- **Programme ID:** EXP-LANG-017

## Purpose

EXP-0022 demonstrated that granting execute authority to a dynamically linked
runtime file is insufficient under Landlock: the kernel also opens the ELF
interpreter during `exec`. This experiment tests a narrow repair that discovers,
resolves, hashes, records, and grants execute authority to the exact registered
interpreter without granting execute authority to an entire system directory.

## Frozen and changed surfaces

The EXP-0018 contract, three subjects, 30 positive slots, 21 authority probes,
concurrent scheduling, output expectations, and non-reuse rule remain frozen.
The only intended semantic change from EXP-0022 is a new role:
`runtime-loader-executable`.

For every runtime, the runner must:

1. extract exactly one absolute `PT_INTERP` path from the runtime ELF image;
2. resolve it to one regular file without a reparse or symlink cycle;
3. record the requested path, resolved path, SHA-256, size, and mode;
4. pass the resolved path to the native launcher; and
5. grant that file, and only that file, Landlock read and execute authority.

The broad system roots remain read-only. `/usr/bin/true` remains the registered
unapproved-executable probe and must be denied.

## Questions

1. **Q1 — Does the exact loader closure restore permitted execution?** Pass
   only if all 30 positive Python, Node, and Rust slots complete with their
   exact outputs.
2. **Q2 — Does the repair preserve authority denial?** Pass only if all 21
   frozen probes reach their intended operations, are denied with exact
   classifications, and emit no reusable evidence.
3. **Q3 — Is loader authority exact and identity-bound?** Pass only if every
   slot records one loader artifact and any path, digest, size, mode, alias, or
   broad-directory-execute mutation is rejected.
4. **Q4 — Do independent validators agree?** Pass only if Rust and Python emit
   byte-identical reports and reject every registered attack exactly.
5. **Q5 — Is the boundary stable and non-mutating?** Pass only if the host
   exposes Landlock ABI 4 or newer, the reviewed tree remains unchanged, no
   container boundary is counted, and the full run stays below 60 seconds.

## Decision rule

- **Pass:** Q1–Q5 pass on a supported native Linux host.
- **Revise:** exact loader execution works but another bounded criterion fails.
- **Unanswered:** the native mechanism is unavailable and zero workload
  receipts are emitted.
- **Stop:** the repair grants directory-wide execute authority, permits an
  unregistered executable, falls back, or makes denied evidence reusable.

The immutable registration is [preregistration.json](preregistration.json).
The outcome and retained identities are summarized in
[CONCLUSION.md](CONCLUSION.md).
