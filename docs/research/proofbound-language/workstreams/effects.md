# WS-FX: effects and capabilities

- **Status:** EXP-LANG-015 / Experiment 0022 concluded `revise`
- **Hypotheses:** H5, H9
- **Depends on:** WS-IR authority and dependency model
- **Blocks:** Gate 2

## Objective

Represent and constrain authority such as reads, ephemeral and reviewed writes,
tool execution, environment access, network, clock, randomness, secrets, and
human judgment.

## Method

Model current mutation and packaging operations, then replay known ambient
plugin, root-write, lifecycle-script, environment, symlink, and subprocess
smuggling defects.

EXP-LANG-003 makes the first experiment narrower and testable: compare an
enforced effect boundary with declaration-only and global-revision cache
strategies against the retained undeclared-read falsifier and representative
mutation/distribution operations.

## Concluded experiment

[EXP-LANG-005 / Experiment 0012](../../../experiments/0012-effect-checked-replay/README.md)
tests a mediated effect machine, the retained hidden-read falsifier, bounded
mutation and distribution workloads, and honest opaque/external subprocess
boundaries. It does not claim that existing adapters are OS-sandboxed.

Both implementations agreed exactly across six plans, 23 attacks, and ten
repetitions. Mediation repaired the retained invalidation falsifier and the two
representative routes completed without ambient authority. Opaque processes
remained non-reusable. The synthetic external receipt tested only type and
identity binding, so real sandbox enforcement remains a separate prerequisite
for production adoption.

## Exit criteria

At least two demonstrated defects fail before expensive execution, observed
effects cannot exceed declared effects, and OS-enforced versus language-level
guarantees remain explicit.

The research exit criteria pass for the bounded interpreter. They do not
authorize claiming that current adapters enforce the same boundary.

## OS-enforced result

[EXP-LANG-011 / Experiment 0018](../../../experiments/0018-os-enforced-effects/README.md)
tested the missing external premise with a separately identified macOS
mechanism. Thirty positive runs completed, all 21 authority probes were denied,
no denied run was reusable, narrow invalidation held, and independent reports
matched across all 30 attacks. The typed boundary is supported for the frozen
corpus. The production exit remains open because the run exceeded its latency
ceiling and does not establish Linux, Windows, or syscall-complete hermeticity.

## Latency repair

[EXP-LANG-012 / Experiment 0019](../../../experiments/0019-batched-enforcement-latency/README.md)
scheduled all 51 independently sandboxed processes concurrently. It completed
in 6,048 ms, preserved distinct per-run roots and receipts, and rejected all
30 inherited and ten scheduler attacks in independent implementations. The
latency criterion is repaired without adopting a shared long-lived worker.
Portability and production mechanism support remain open.

## Linux portability result

[EXP-LANG-013 / Experiment 0020](../../../experiments/0020-linux-enforcement-portability/README.md)
compiled every authority class to an explicit Linux disposition. The
available Linux arm64 VM returned `ENOSYS` for its exact Landlock ABI query,
including without Docker's outer seccomp profile. The executor correctly
emitted no workload receipt and admitted no container or unconfined fallback.
This supports fail-closed availability handling, not Linux enforcement.

## Windows portability result

[EXP-LANG-014 / Experiment 0021](../../../experiments/0021-windows-enforcement-portability/README.md)
compiles the same authority classes to a conjunctive AppContainer,
restricted-token, job-object, and exact-ACL design. No supported Windows 11
host was available. The platform gate emitted zero receipts and no fallback,
so the result makes the policy delta explicit without claiming enforcement.

## Windows confirmation result

[EXP-LANG-016 / Experiment 0023](../../../experiments/0023-windows-enforcement-confirmation/README.md)
ran on native Windows 11 ARM64. The launcher verified a suspended AppContainer
child at low integrity, deny-only Administrators, and inside the one-process
job before resume. The staged signed process then terminated with
`STATUS_DLL_INIT_FAILED` before workload entry. The result is `revise` with
zero reusable evidence: the next candidate must preregister the minimum Windows
executable, DLL, profile, registry, and object-manager initialization closure.

## Linux confirmation result

[EXP-LANG-015 / Experiment 0022](../../../experiments/0022-linux-enforcement-confirmation/README.md)
ran the frozen Linux corpus on an Ubuntu ARM64 host with Landlock ABI 7. All
51 slots reached the native launcher, but all 30 permitted workloads failed at
runtime execution. The candidate named the dynamic-loader premise without
granting its exact execute closure. The next candidate must bind that closure
without turning broad system-read roots into executable authority.

## Linux loader-closure result

[EXP-LANG-017 / Experiment 0024](../../../experiments/0024-linux-loader-closure/README.md)
registered the ELF interpreter as a distinct exact artifact role. On Landlock
ABI 7, all 30 permitted runs completed and all 21 attacks remained denied and
non-reusable. The system roots retained read-only authority, while only the
identity-bound interpreter gained execution authority. Rust and Python reports
were byte-identical and both rejected all 20 registered attacks exactly.

This closes the bounded Linux loader falsifier. It does not establish arbitrary
platform closure discovery; EXP-LANG-016 independently shows that Windows needs
its own explicit initialization closure.

## Windows initialization-closure result

[EXP-LANG-018 / Experiment 0025](../../../experiments/0025-windows-initialization-closure/README.md)
adds that explicit closure. Native Windows 11 ARM64 executes Python, Node, and
Rust beneath the AppContainer, restricted-token, one-process-job, private-
desktop, exact-ACL, and identity-bound runtime boundary. Twenty Node/Rust
workloads complete exactly, eighteen probes prove denial, all thirty closure
attacks reject, and independent reports agree within the latency ceiling.

The result is `revise`, not cross-platform confirmation. Python's text-mode
writer converts the frozen LF result to CRLF, while the network probes observe
connection-refused rather than access denied. Both remain non-reusable. The
next study must preregister platform-neutral output bytes and a reachable
network oracle while retaining the successful initialization closure.

[EXP-LANG-019 / Experiment 0026](../../../experiments/0026-windows-output-network-confirmation/README.md)
is that preregistered study. Its network oracle includes a same-subject control
connection, an unchanged live endpoint, listener acceptance counts, exact
native denial classes, and proof that the fresh AppContainer SID is absent
from Windows' loopback-exemption set.
