# Experiment 0025 journal

[Experiment registration](README.md) · [Artifact ledger](ARTIFACTS.md)

This journal distinguishes diagnostic and instrumentation runs from the final
confirmation. No failed or partial diagnostic run emitted reusable assurance
evidence.

## 2026-09-04 — Preregistered

Registered the exact Windows initialization-closure experiment after
EXP-0023 reached the native Windows 11 ARM64 boundary but terminated before
workload entry. The EXP-0018 subjects, arguments, output bytes, 30 positive
slots, 21 authority probes, non-reuse rule, and 60-second ceiling remained
frozen. Discovery authority could identify a candidate but could not count as
confirmation evidence.

## 2026-09-04 — Candidate and native runner implemented

Implemented the AppContainer runner, restricted low-integrity token, suspended
job assignment, private desktop, exact environment, output capture, staged
file identities and ACLs, and independently checked initialization-closure
record. The candidate records native architecture, resolved runtime artifacts,
file IDs, hashes, sizes, security descriptors, reparse state, the private
drive alias, and AppContainer profile state.

## 2026-09-04 — Diagnostic corrections

Several native runs stopped before a valid confirmation result. They exposed
instrument defects rather than experiment outcomes:

- a tracing attempt did not export its initialization trace;
- the Rust compiler wrapper contaminated strict tool-identity output;
- Git checkout converted the frozen LF corpus to CRLF before execution;
- an unconstrained capture exceeded the registered result-size bound;
- an unrelated x86 compatibility DLL entered an ARM64 artifact inventory;
- Node attempted metadata resolution through an unregistered drive-root path;
- AppContainer profile deletion temporarily failed with a sharing violation;
  and
- initial denial classification treated a documented job quota result and an
  ambiguous connection-refused result incorrectly.

Each correction tightened the instrument or made an already-required identity
explicit. The candidate used by the retained run was frozen before its 51
slots began. Earlier captures remain non-reusable and are not combined with
the retained result.

The final denial classifier follows the native distinction: the one-process
job can report Windows error 1816 (`ERROR_NOT_ENOUGH_QUOTA`) when it refuses a
second process, while connection-refused is not an access-denied result.

## 2026-09-04 — Retained native confirmation

[GitHub run 33822698555](https://github.com/bordumb/proof-bound/actions/runs/33822698555)
completed the 51-slot native Windows 11 ARM64 execution and retained its raw
artifacts. All runtimes reached workload entry. Node and Rust supplied 20 exact
positive executions. Ten Python runs exited zero but produced CRLF bytes and
were retained as incomplete. Eighteen authority probes were definitely denied;
three network probes returned connection-refused and were retained as
incomplete. Every denied or incomplete slot remained non-reusable, and the
reviewed tree remained unchanged.

The Rust and Python validators emitted byte-identical 4,043-byte reports and
byte-identical 3,305-byte attack reports. All 30 registered mutations rejected
with their exact codes. The complete run took 46,422 ms.

## 2026-09-04 — Concluded with revision required

Q1, Q4, and Q5 pass. Q2 fails because only 20 of 30 positive executions match
the exact frozen bytes. Q3 fails because only 18 of 21 probes prove denial.
The immutable overall decision is `revise`. A successor must preregister both
a platform-neutral output contract and a reachable network-denial oracle; this
experiment will not be rewritten to make either observation pass.
