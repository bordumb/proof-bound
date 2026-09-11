# Experiment 0026: exact Windows output and network confirmation

- **Status:** concluded — revise
- **Registered:** 2026-09-04
- **Subject baseline:** `f770cf8f87e43f4b4f3e789a3099db74a22889c8`
- **Predecessor:** [Experiment 0025](../0025-windows-initialization-closure/README.md)
- **Operator:** Codex
- **Programme ID:** EXP-LANG-019

## Purpose

EXP-0025 repaired Windows process initialization and supported the exact
AppContainer boundary, but its frozen overall decision was `revise`. Python
used a text writer that translated LF to CRLF, so only 20 of 30 positives
matched exact bytes. The three network probes connected to a closed port and
received connection-refused, which does not prove that policy denied a
connection to a reachable service.

This experiment changes only those two controls. It freezes a binary output
contract for Python and a live, independently observed network oracle. It
retains the successful initialization closure, the other EXP-0018 corpus
bytes, all non-network authority probes, the no-fallback rule, and every
EXP-0025 closure attack.

## Candidate

### Platform-neutral output

The revised Python subject reads and writes bytes explicitly. Node and Rust
remain byte-exact and unchanged. Every positive execution must create exactly
the registered 32-byte output with SHA-256
`6897a0406cd3b5b1aa1c9fb86c784f443606a03f487d2cc00e9fd1a0e2144d22`.
Exit zero, equivalent text, or newline normalization cannot substitute for
those bytes.

### Reachable network oracle

For each language, the runner must create one fresh TCP listener on
`127.0.0.1` and an operating-system-selected port before either probe. The
exact address, port, listener identity, and AppContainer SID are retained.
The same staged runtime, subject bytes, environment, and network-mode arguments
are first executed outside AppContainer. That diagnostic control must connect,
be accepted by the listener, exit zero, and write the exact 17-byte
`network-observed\n` output. It is never reusable evidence.

The listener remains active at the same endpoint for the sandboxed attempt.
That attempt must reach its connect operation, create no output, receive the
registered access-denied result, and produce no accepted listener connection.
Python and Rust must retain native socket error 10013; Node must retain
`EACCES`. Connection-refused, timeout, unreachable-host, a missing listener,
or a changed endpoint is incomplete, not denied.

The runner must query `NetworkIsolationGetAppContainerConfig` before and after
execution and prove the fresh AppContainer SID is absent from the loopback-
exemption set. No network capability or loopback exemption may be added.

Microsoft documents that an AppContainer without a network capability cannot
access the network in [Launch an
AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
and that `NetworkIsolationGetAppContainerConfig` returns the SIDs allowed to
send [loopback
traffic](https://learn.microsoft.com/en-us/windows/win32/api/networkisolation/nf-networkisolation-networkisolationgetappcontainerconfig).

## Frozen surfaces

- Native `windows-11-arm` and Windows 11 ARM64 remain mandatory.
- The EXP-0025 AppContainer, restricted low-integrity token, administrator
  deny-only SID, one-process job, private desktop, drive alias, exact runtime
  closure, ACL, environment, tree, and non-reuse requirements are unchanged.
- The Node and Rust subjects and all non-subject EXP-0018 corpus files retain
  their exact registered identities.
- The revised [corpus index](corpus/index.json) is the only subject change.
- All 30 EXP-0025 adversarial checks remain required, plus eight successor
  attacks registered below.
- Discovery, listener controls, and incomplete runs never emit reusable
  evidence.

## Questions

1. **Q1 — Do all 30 permitted workloads complete byte-exactly?** Ten Python,
   ten Node, and ten Rust executions must exit zero and produce the exact
   32-byte output without normalization.
2. **Q2 — Are all 21 authority probes definitely denied?** The eighteen
   retained non-network probes must keep their exact denial classes. Each of
   the three network controls must connect to its live endpoint; each
   sandboxed network probe must receive its exact access denial, create no
   output, and produce no listener acceptance. Every denied receipt is
   non-reusable.
3. **Q3 — Is the repaired candidate exact?** The 30 inherited attacks and all
   eight output/oracle attacks must reject with their registered codes. The
   initialization closure and sandbox authority cannot expand.
4. **Q4 — Do independent validators agree?** Rust and Python must emit
   byte-identical semantic and attack reports, independently rederive all
   question values, bind listener and exemption observations, and reject
   forged reuse or decision fields.
5. **Q5 — Does the complete confirmation remain feasible and non-mutating?**
   All slots and controls must finish within 60,000 ms, the reviewed tree must
   remain byte-identical, and no execution may fall back.

## Eight successor attacks

| ID | Mutation | Exact code |
|---|---|---|
| EXP-0026-A031 | Substitute the revised corpus or binary-output identity | `WIN26-CORPUS` |
| EXP-0026-A032 | Restore Python text-mode newline translation | `WIN26-BINARY-OUTPUT` |
| EXP-0026-A033 | Omit or fail the unsandboxed reachability control | `WIN26-ORACLE-CONTROL` |
| EXP-0026-A034 | Change the listener address or port between probes | `WIN26-ORACLE-ENDPOINT` |
| EXP-0026-A035 | Classify connection-refused, timeout, or unreachable as denied | `WIN26-NETWORK-DENIAL` |
| EXP-0026-A036 | Mark a listener-accepted sandbox connection as denied | `WIN26-NETWORK-ACCEPTED` |
| EXP-0026-A037 | Add a network capability or loopback exemption | `WIN26-NETWORK-CAPABILITY` |
| EXP-0026-A038 | Forge validator agreement, a question value, reuse, or decision | `WIN26-REPORT` |

## Decision rule

- **Pass:** Q1–Q5 pass on native Windows 11 ARM64.
- **Revise:** the exact candidate executes but any bounded output, denial,
  exactness, independent-validation, or feasibility criterion fails.
- **Unanswered:** the eligible native runner, listener, or required network-
  isolation API is unavailable and no workload receipt is emitted.
- **Stop:** the sandbox is weakened, a capability or exemption is added,
  controls count as assurance evidence, an ambiguous network result is called
  denied, a denied/incomplete result becomes reusable, or execution falls back.

The machine-readable registration is [preregistration.json](preregistration.json).
No EXP-0026 runner, validator, capture, or result existed at registration.

## Conclusion

The native Windows 11 ARM64 run completed all registered work and retained an
honest `revise` decision. All 30 permitted workloads produced the exact bytes;
all 18 non-network authority probes were denied; and no denied or incomplete
execution was reusable. Each unsandboxed network control connected to its live
loopback listener, while no sandboxed connection was accepted and no
AppContainer SID appeared in the loopback-exemption set.

Q2 nevertheless fails under the preregistered rule. Node and Python observed
connection timeouts, and Rust reached the process deadline. Those observations
are consistent with network isolation but are not the exact `EACCES` / Winsock
10013 results required to classify a definite denial. All three remain
`incomplete` and non-reusable. Both independent validators agreed byte for
byte, all 38 attacks rejected exactly, the reviewed tree was unchanged, and
the 58,609 ms run stayed below the 60,000 ms ceiling.

See the [conclusion](CONCLUSION.md), [journal](JOURNAL.md), [artifact
ledger](ARTIFACTS.md), and [checked-in results](results/README.md).
