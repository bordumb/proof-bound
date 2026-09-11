# Experiment 0026 conclusion

[Registration](README.md) · [Machine result](results/execution.json) ·
[Journal](JOURNAL.md) · [Artifacts](ARTIFACTS.md)

- **Decision:** revise
- **Executed / concluded:** 2026-09-04 / 2026-09-04
- **Scope:** GitHub-hosted native Windows 11 ARM64, version `10.0.26200`

## Result

EXP-0026 repaired the platform-dependent output defect from EXP-0025. Ten
Python, ten Node, and ten Rust workloads all exited zero and emitted the exact
registered 32-byte output. The same AppContainer, low-integrity restricted
token, deny-only Administrators SID, one-process job, private desktop, exact
runtime closure, drive alias, ACL, environment, and no-fallback boundary
remained in force. Q1 passes.

The live network oracle also resolved the predecessor's closed-port defect.
For each runtime, the same staged subject first connected outside the sandbox
to a fresh live `127.0.0.1` listener, was accepted, exited zero, and wrote the
exact 17-byte control output. Each sandboxed attempt then reached the same
endpoint without a network capability or loopback exemption. None connected,
none wrote output, and none emitted reusable evidence.

The overall decision remains **revise** because the native failure form did not
meet the frozen exact-denial criterion. Node returned `ETIMEDOUT`, Python
returned `TimeoutError`, and Rust remained blocked until the process deadline.
The listener evidence establishes zero accepted sandbox connections, but a
timeout is not Winsock 10013 and is not Node `EACCES`. The validators therefore
retain all three observations as incomplete, not denied. Q2 fails with 18 of
21 probes definitely denied.

Q3 and Q4 pass. The independent Python and Rust implementations produced
byte-identical semantic reports and byte-identical attack reports. All 30
inherited initialization attacks and all eight successor output/oracle attacks
were rejected with their exact registered codes. Q5 passes: no denied or
incomplete receipt was reusable, the reviewed tree did not change, no fallback
ran, and the complete experiment took 58,609 ms beneath the 60,000 ms ceiling.

## What the experiment establishes

The bounded Windows execution candidate now supports exact permitted output
for Python, Node, and Rust. It also supplies materially stronger network
evidence than connection-refused: the endpoint was live, the identical
unsandboxed subjects connected, all three sandboxed attempts reached their
connect operations, zero sandbox connections were accepted, and the queried
AppContainer SIDs had neither capabilities nor loopback exemptions.

It does not establish the preregistered exact network-denial claim. Windows can
enforce a packet-drop-style boundary whose user-space manifestation is timeout
rather than a synchronous access-denied error. Proofbound must represent that
difference instead of forcing every platform into one error-code vocabulary.
The observation is strong enough to inform the next model, but not to rewrite
this experiment's immutable acceptance rule.

This is also an example of the desired notification discipline: the useful
signal is not “CI failed” or “network test timed out.” The run completed, the
positive and filesystem/process/environment claims remain supported, and one
precise obligation remains open—classifying independently observed network
non-delivery without overstating it as a synchronous denial.

## Boundaries and non-claims

- The tested corpus is 30 small Python, Node, and Rust processes, not package
  managers, native extensions, child-process trees, interactive applications,
  remote services, UDP, IPv6, DNS, or distributed systems.
- The listener proves local reachability and independently observes accepted
  TCP connections. It does not expose kernel packet-drop telemetry or prove
  why an unaccepted attempt timed out.
- Absence from `NetworkIsolationGetAppContainerConfig` proves that the fresh
  SID was not loopback-exempt at the two query points. It is not a complete
  verification of every Windows filtering layer.
- The exact closure is bound to the identified GitHub Windows 11 ARM64 runner
  and runtime artifacts. It does not establish x86-64 or self-hosted parity.
- The result supports bounded Windows execution and isolation observations,
  not syscall-complete hermeticity or production cache authority.

## Next research

Do not rerun this corpus merely hoping for a different error string. The next
candidate should define a platform-neutral network outcome algebra separating
`synchronous-denial`, `observed-non-delivery`, `accepted`, and `unobserved`,
with explicit observation authority and time bounds. It should then test a
Windows Filtering Platform or Event Tracing for Windows observer, if one can
attribute the attempted flow without adding authority to the subject. A new
preregistration can decide whether independent kernel observation upgrades
bounded non-delivery to a reusable denial fact.

## Platform references

- Microsoft documents AppContainer network capabilities in
  [Implementing an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).
- Microsoft documents the loopback-exemption query and ownership rules in
  [`NetworkIsolationGetAppContainerConfig`](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-networkisolationgetappcontainerconfig).
- Microsoft defines Winsock 10013 as `WSAEACCES` in
  [Windows Sockets error codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2).
