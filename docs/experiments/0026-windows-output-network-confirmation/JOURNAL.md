# Experiment 0026 journal

[Experiment registration](README.md) · [Artifact ledger](ARTIFACTS.md)

This journal distinguishes diagnostic and instrumentation runs from the final
confirmation. Failed or partial runs produced no reusable assurance evidence.

## 2026-09-04 — Preregistered

Registered a successor to EXP-0025 before implementing its runner or
validators. The successor changed only the Python byte-emission contract and
the network oracle. It retained the exact Windows initialization closure, 30
positive slots, 18 non-network authority probes, no-fallback and non-reuse
rules, 60-second ceiling, 30 inherited attacks, and added eight oracle attacks.

## 2026-09-04 — Candidate implemented

Implemented one native executor and independent Python and Rust validators.
The executor uses binary Python output, fresh live loopback listeners,
same-subject unsandboxed controls, listener acceptance observations, and the
documented `NetworkIsolationGetAppContainerConfig` API. It records the exact
endpoint, runtime and subject identities, fresh AppContainer SID, exemptions
before and after, native process result, captured output, and reuse state.

## 2026-09-04 — Diagnostic corrections

Several native runs exposed instrument defects before a complete confirmation:

- the initial control listener waited synchronously and deadlocked the subject;
- AppContainer profile cleanup entered an indeterminate access-denied state and
  needed the bounded repeat-delete procedure required by the Windows API;
- the sandbox listener was observed only after waiting for the process, which
  could not distinguish a connection from a blocked connect;
- the boundary discarded a complete network observation when the subject
  reached its process deadline; and
- the inherited Python error adapter did not preserve its structured message
  during adversarial validation.

Each correction repaired orchestration or preserved a more conservative
result. None changed the registered denial rule. The final candidate treats a
timeout or process deadline as incomplete and non-reusable, never as access
denied. Earlier captures are not combined with the retained result.

## 2026-09-04 — Retained native confirmation

[GitHub run 33827784782](https://github.com/bordumb/proof-bound/actions/runs/33827784782)
completed the full native Windows 11 ARM64 confirmation. All 30 positive
workloads emitted exact output, and all 18 non-network probes were definitely
denied. The three controls connected to their live listeners; the three
sandbox attempts produced zero accepted connections and no output. No fresh
AppContainer SID was loopback-exempt before or after execution.

Node and Python timed out while connecting, and Rust reached the process
deadline. Those are not the exact registered access-denied results, so all
three network attempts remain incomplete and non-reusable. The complete run
took 58,609 ms and left the reviewed tree unchanged.

The Python and Rust validators emitted byte-identical 5,081-byte semantic
reports and byte-identical 4,181-byte attack reports. All 38 registered
mutations rejected with their exact codes.

## 2026-09-04 — Concluded with revision required

Q1, Q3, Q4, and Q5 pass. Q2 fails because the native network observations are
strong non-delivery evidence but do not have the exact synchronous denial form
frozen by the registration. The immutable overall decision is `revise`. A
successor may test a typed non-delivery outcome and independent kernel observer;
this experiment will not relabel timeouts as access denials.
