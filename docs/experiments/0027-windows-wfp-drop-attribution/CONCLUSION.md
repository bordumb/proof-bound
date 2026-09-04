# Experiment 0027 conclusion

[Registration](README.md) · [Machine result](results/execution.json) ·
[Journal](JOURNAL.md) · [Artifacts](ARTIFACTS.md)

- **Decision:** revise
- **Executed / concluded:** 2026-09-04 / 2026-09-04
- **Scope:** GitHub-hosted native Windows 11 ARM64, version `10.0.26200`

## Result

EXP-0027 executed the unchanged EXP-0026 corpus under a separately identified,
read-only Windows Filtering Platform observer. The observer successfully
queried `FWPM_ENGINE_COLLECT_NET_EVENTS`, subscribed with
`FwpmNetEventSubscribe1`, and confirmed that collection remained enabled. It
changed no collection option, filter, firewall state, subject capability, or
loopback exemption.

All 30 permitted Python, Node, and Rust workloads emitted their exact output.
All 18 non-network authority probes were definitely denied. All three
same-subject controls connected to fresh live loopback listeners, while zero
of three AppContainer attempts connected or wrote output. No denied or
incomplete execution was reusable, and the reviewed tree did not change.

The decision is nevertheless **revise**. The observer received zero capability-
drop events, and none of the three runtimes returned the registered synchronous
access-denied marker. Each network attempt therefore remains the typed outcome
`bounded-non-delivery`, not a definite authority denial. Q2 fails with zero of
three network attempts attributable to either accepted denial mechanism.

Q1, Q3, Q4, and Q5 pass. Independent Python and Rust validators emitted byte-
identical semantic reports and byte-identical attack reports. All 38 inherited
attacks and all ten WFP successor attacks rejected with their exact codes. The
complete execution took 54,015 ms, beneath the frozen 60,000 ms ceiling.

## What the experiment establishes

The Windows boundary repeatedly prevents these three sandboxed TCP loopback
connections in the tested environment: the endpoint is live, the identical
unsandboxed subject connects, and the AppContainer subject does not. The new
outcome algebra also prevents that useful operational observation from being
misreported as a proven policy denial.

The experiment also shows that read-only subscription to the documented WFP
net-event stream is not sufficient on this GitHub Windows 11 ARM host. Event
collection was enabled and the subscription was active across all attempts,
yet no capability-drop record was delivered. This is a negative result about
this observation mechanism, not evidence that the connection was accepted.

For notification quality, the correct signal is now narrow: 48 of 51 authority
checks are classified exactly, all operational containment checks succeeded,
and three network-policy explanations remain unresolved. A generic red build
would obscure that distinction; promoting the three observations to denial
would overstate it.

## Boundaries and non-claims

- Zero accepted connections is bounded non-delivery, not proof of the Windows
  filtering layer or rule that caused it.
- An enabled WFP collector and successful subscription do not guarantee that
  every relevant packet disposition produces a capability event.
- The study covers TCP/IPv4 loopback for three small runtimes on one Windows 11
  ARM64 runner image. It does not cover remote networking, DNS, UDP, IPv6,
  x86-64, self-hosted policy, package managers, or native extensions.
- The synthetic event mutations test rejection behavior only. They are not
  substituted for missing live events and contribute no positive evidence.
- The result supports exact bounded execution and non-delivery observation; it
  does not authorize reusable network-denial evidence.

## Next research

Do not keep adding uncorrelated Windows telemetry backends. First inspect the
WFP filter and audit configuration that governs these AppContainer attempts,
then preregister one diagnostic experiment that can distinguish at least:
packet-policy drop, transport isolation, namespace or broker mediation, and
runtime/process deadline. Candidate mechanisms must expose a documented,
stable subject-and-flow correlation key and remain read-only. If Windows does
not expose that attribution without privileged host mutation, Proofbound
should retain `bounded-non-delivery` as the strongest portable result and make
stronger Windows denial evidence an explicitly host-provisioned capability.

## Platform references

- Microsoft defines the common event fields, including package SID,
  application ID, addresses, ports, protocol, and timestamp, in
  [`FWPM_NET_EVENT_HEADER2`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_header2).
- Microsoft documents capability-drop attribution, including missing
  capability, filter ID, and loopback disposition, in
  [`FWPM_NET_EVENT_CAPABILITY_DROP0`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_capability_drop0).
- Microsoft documents the subscription access requirement and callback API in
  [`FwpmNetEventSubscribe1`](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe1).
