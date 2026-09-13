# Cross-platform enforcement synthesis

[Programme dashboard](../README.md) · [Effects workstream](../workstreams/effects.md) ·
[Language direction](../decisions/0001-language-direction.md)

- **Status:** current synthesis
- **Date:** 2026-09-04
- **Scope:** Experiments 0018--0027; bounded Python, Node, and Rust subjects

## Executive result

Proofbound can execute the same small, registered workload family under real
OS boundaries on macOS, Linux, and Windows without granting unrestricted
project authority. It cannot honestly expose one uniform cross-platform
“denied” bit.

macOS and Linux satisfy the complete frozen permitted/denied corpus. Windows
satisfies exact permitted execution and all non-network denials, and repeatedly
prevents the sandboxed network connections operationally. Windows does not,
however, expose the registered causal denial evidence for those three network
attempts. The portable result is therefore a typed observation algebra, not a
promise that every host can prove every denial.

## Evidence matrix

| Property | macOS | Linux | Windows 11 ARM64 |
|---|---:|---:|---:|
| Exact permitted executions | 30 / 30 | 30 / 30 | 30 / 30 |
| Exact non-network authority denials | 18 / 18 | 18 / 18 | 18 / 18 |
| Network attempts operationally contained | 3 / 3 | 3 / 3 | 3 / 3 |
| Network attempts admitted as definite denial | 3 / 3 | 3 / 3 | 0 / 3 |
| Reusable denied/incomplete results | 0 | 0 | 0 |
| Complete run beneath 60 seconds | 6,048 ms | 3,101 ms | 54,015 ms |
| Independent semantic validators agree | yes | yes | yes |
| Retained decision | pass | pass | revise |

Sources: [macOS batching](../../../experiments/0019-batched-enforcement-latency/CONCLUSION.md),
[Linux exact loader](../../../experiments/0024-linux-loader-closure/CONCLUSION.md),
[Windows exact output and live oracle](../../../experiments/0026-windows-output-network-confirmation/CONCLUSION.md),
and [Windows WFP attribution](../../../experiments/0027-windows-wfp-drop-attribution/CONCLUSION.md).

The “operationally contained” row means the registered attempt produced no
accepted connection or reusable output within its bounded oracle. It is not
equivalent to the “definite denial” row, which additionally requires the
registered causal evidence.

## Portable contract

```text
logical effect policy
        |
        v
platform plan + exact closure
        |
        v
typed observation
  completed
  synchronous-denial
  attributed-denial
  bounded-non-delivery
  unsupported
  accepted
        |
        v
claim-specific reuse decision
```

Only observations justified by the active platform profile may strengthen a
claim. Unsupported evidence stays explicit. `bounded-non-delivery` can support
a bounded reachability observation, but cannot be silently coerced into a
policy denial. `accepted` falsifies containment. Denied, incomplete, and
unsupported runs never become reusable positive evidence.

## Architecture consequences

1. **The IR owns meaning; adapters own mechanisms.** App Sandbox, Landlock,
   seccomp, AppContainer, WFP, and future observers remain backend records
   beneath a small common outcome algebra.
2. **Platform profiles are capability-typed.** A host advertises which effects
   it can enforce and which denial causes it can attest. Compilation fails or
   weakens the requested claim explicitly when a capability is absent.
3. **Exact closures remain platform-specific.** Runtime loaders, staged DLLs,
   interpreters, and OS instruments are identity-bound inputs, not hidden
   implementation details.
4. **Evidence strength is monotone and claim-local.** A stronger backend may
   discharge an obligation; a weaker backend cannot rename its observation to
   match. Unrelated claims need not be invalidated.
5. **Notification severity follows consequence.** The useful Windows signal is
   one unresolved network-attribution obligation, not a generic failure of 51
   workloads. Exact positive and non-network results remain visible.

## What remains open

- broader workloads, child-process graphs, native extensions, package managers,
  DNS, UDP, IPv6, and remote services;
- production-safe lifecycle and performance beyond the bounded corpus;
- Windows network-denial attribution on a deliberately provisioned host;
- source-aware diagnostics and authoring ergonomics; and
- measured human benefit from claim-oriented uncertainty and notification
  reduction.

These gaps limit the product claim. They do not erase the demonstrated common
semantic core or justify replacing typed evidence with lowest-common-
denominator booleans.
