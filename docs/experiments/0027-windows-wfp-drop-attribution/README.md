# Experiment 0027: Windows WFP drop attribution

- **Status:** preregistered — not executed
- **Registered:** 2026-09-04
- **Subject baseline:** `96206dc3b8bb95c3124c7c41aab31c8cea822658`
- **Predecessor:** [Experiment 0026](../0026-windows-output-network-confirmation/README.md)
- **Operator:** Codex
- **Programme ID:** EXP-LANG-020

## Purpose

EXP-0026 successfully executed all 30 permitted workloads and observed the
desired network behavior: three identical unsandboxed controls connected to
live loopback listeners, while zero of three AppContainer attempts connected,
wrote output, or produced reusable evidence. Its decision was nevertheless
`revise` because Windows exposed two timeouts and one process deadline rather
than the preregistered synchronous access-denied codes.

This successor tests whether the Windows Filtering Platform (WFP) can supply
the missing attribution. It does not relax a timeout into a denial. A network
attempt becomes definitely denied only if an independently running, read-only
observer receives a WFP AppContainer capability-drop event bound to the fresh
AppContainer SID, exact staged application, TCP loopback endpoint, and bounded
execution window. Otherwise the attempt remains incomplete and non-reusable.

## Candidate

### Typed network outcomes

The candidate distinguishes four outcomes:

- `synchronous-denial`: the subject receives the registered native access-
  denied result;
- `capability-drop-denial`: WFP independently reports an AppContainer
  capability drop for the exact attempted flow;
- `bounded-non-delivery`: the live listener accepts no connection before the
  deadline, but no fully bound WFP drop exists; and
- `accepted`: the live listener accepts the sandboxed connection.

Only the first two are definite denials. `bounded-non-delivery` is an honest
observation but cannot authorize reuse or satisfy the denial question.
`accepted` falsifies the candidate.

### Read-only WFP observer

Before any workload executes, the parent must open the WFP engine and query
`FWPM_ENGINE_COLLECT_NET_EVENTS` with `FwpmEngineGetOption0`. Collection must
already be enabled. The experiment must not call `FwpmEngineSetOption0`, add or
remove a filter, change firewall state, enable ETW, or otherwise mutate the
host network policy. Missing access, a disabled collector, or an unavailable
API yields `unanswered` with zero workload receipts.

For each sandboxed network attempt, a fresh observer subscription must exist
before the process resumes. Every accepted capability-drop event must contain:

- event type `FWPM_NET_EVENT_TYPE_CAPABILITY_DROP`;
- the `FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET`,
  `FWPM_NET_EVENT_FLAG_APP_ID_SET`, protocol, IP-version, remote-address, and
  remote-port flags;
- the exact fresh AppContainer SID;
- the application ID independently derived from the exact staged executable
  with `FwpmGetAppIdFromFileName0`;
- IPv4, TCP, remote address `127.0.0.1`, and the exact live listener port;
- a timestamp after subscription and before the bounded observation closes;
- `isLoopback = true`, a defined missing AppContainer network capability, and
  a nonzero enforcing WFP filter ID; and
- an identity-bound canonical event record retained before profile teardown.

At least one fully bound event is required. Multiple retries are allowed only
when every retained matching event satisfies the same bindings. An allow event,
listener acceptance, endpoint mismatch, missing SID/application field, event
outside the window, or unresolvable event structure cannot be called denied.

Microsoft documents that WFP exposes a distinct AppContainer capability-drop
event, including the missing capability, enforcing filter ID, and loopback
flag, in
[`FWPM_NET_EVENT_CAPABILITY_DROP0`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_capability_drop0).
The event header carries the package SID, application ID, protocol, addresses,
ports, and timestamp in
[`FWPM_NET_EVENT_HEADER2`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_header2).

## Frozen surfaces

- The EXP-0026 corpus, binary output contract, candidate, initialization
  closure, platform gate, 30 positive slots, 18 non-network authority probes,
  three live controls, and three sandbox network attempts are unchanged.
- Native Windows 11 ARM64 remains mandatory.
- Each listener remains live and unchanged across its same-subject control and
  sandbox attempt.
- AppContainer capabilities and loopback exemptions remain empty.
- All 38 predecessor attacks remain required, plus ten WFP-attribution attacks.
- The observer is a separately identified parent-side instrument. Its source,
  compiler invocation, executable bytes, architecture, and WFP API version are
  captured in the closure; it adds no authority to the subject.
- Denied and incomplete executions never emit reusable evidence.

## Questions

1. **Q1 — Does exact execution remain intact?** All 30 permitted workloads
   must emit the exact registered bytes, and all 18 non-network probes must
   retain their exact denial classes without reusable evidence.
2. **Q2 — Does WFP definitely attribute all three network drops?** All three
   controls must connect to their live endpoints. No sandbox connection may be
   accepted or write output. Every sandbox attempt must receive either its
   exact synchronous denial or at least one fully bound WFP capability-drop
   event. All three must be definitely denied and non-reusable.
3. **Q3 — Is the observer-bound candidate exact?** The 38 inherited attacks
   and all ten successor attacks must reject with their exact registered codes;
   the observer cannot expand subject or host policy authority.
4. **Q4 — Do independent validators agree?** Rust and Python must emit byte-
   identical semantic and attack reports, independently bind every WFP field,
   derive the typed outcomes and Q1--Q5, and reject forged attribution.
5. **Q5 — Is confirmation feasible and non-mutating?** The full experiment
   must complete within 60,000 ms, preserve the reviewed tree and WFP collection
   setting, use no fallback, and emit no reusable evidence for denied or
   incomplete execution.

## Ten successor attacks

| ID | Mutation | Exact code |
|---|---|---|
| EXP-0027-A039 | Substitute observer source, executable, architecture, invocation, or API version | `WIN27-OBSERVER` |
| EXP-0027-A040 | Forge WFP availability or change the collection setting | `WIN27-COLLECTION` |
| EXP-0027-A041 | Replace capability-drop with another WFP event type | `WIN27-EVENT-TYPE` |
| EXP-0027-A042 | Substitute or omit the package SID or application ID | `WIN27-SUBJECT` |
| EXP-0027-A043 | Substitute protocol, IP version, loopback address, or port | `WIN27-FLOW` |
| EXP-0027-A044 | Move the event outside the subscribed execution window | `WIN27-WINDOW` |
| EXP-0027-A045 | Remove loopback, missing-capability, or enforcing-filter attribution | `WIN27-DROP` |
| EXP-0027-A046 | Hide a listener acceptance, output, or WFP allow event | `WIN27-ACCEPTED` |
| EXP-0027-A047 | Classify non-delivery without a fully bound event as denied | `WIN27-ATTRIBUTION` |
| EXP-0027-A048 | Forge outcome counts, reuse, question values, agreement, or decision | `WIN27-REPORT` |

## Decision rule

- **Pass:** Q1--Q5 pass on native Windows 11 ARM64.
- **Revise:** the eligible observer and exact candidate execute, but any
  workload, denial, attribution, exactness, agreement, or feasibility criterion
  fails.
- **Unanswered:** WFP event collection is disabled, the read-only observer
  lacks required access, or the required API is unavailable before workloads;
  no workload receipt may be emitted.
- **Stop:** the implementation changes WFP collection or firewall state, adds
  subject capability or exemption, treats non-delivery alone as denial,
  accepts an incompletely bound event, makes a denied/incomplete result
  reusable, changes the frozen corpus, or uses a fallback.

The machine-readable registration is [preregistration.json](preregistration.json).
No EXP-0027 observer, runner, validator, capture, or result exists at
registration.
