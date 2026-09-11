# Experiment 0022 conclusion

Experiment 0022 concludes **revise**. GitHub's native Ubuntu 24.04 ARM64 host
exposed Landlock ABI 7, `no_new_privs`, and seccomp. The frozen EXP-0020
runner therefore crossed the availability gate and executed all 51 registered
slots, but its filesystem policy denied every runtime at `exec`.

## Result

- The host was Linux ARM64 with kernel `6.17.0-1022-azure`.
- The native launcher reported Landlock ABI 7.
- All 30 permitted executions failed with `runtime-exec: Permission denied`.
- All 21 authority probes failed at the same earlier boundary.
- No denied execution was reusable.
- The reviewed tree remained byte-identical.
- Both the Rust validator in CI and an independent local Python replay rejected
  the capture with `LNX-POSITIVE-OUTCOME`.

The experiment therefore establishes mechanism availability but not correct
project authority. The authority probes do not count as successful attack
denials because the registered workloads never entered: the policy denied the
runtime before any probe could exercise its intended authority.

## Finding

The frozen launcher grants read authority to its registered system roots and
grants execute authority to the requested runtime file. On the supported host,
that is insufficient for a dynamically linked executable: the kernel must also
execute the registered ELF interpreter. The current policy does not grant
execute authority to that loader boundary.

The failure is useful because EXP-0020 identified the dynamic-loader premise
in prose, while EXP-0022 shows that the effective enforcement policy did not
actually encode it. A successor experiment must register the exact runtime and
loader execution closure, not grant executable authority to every file beneath
the broad system-read roots.

## Next evidence

A new preregistered Linux repair should preserve all 30 positive workloads, 21
authority probes, and independent validators while adding an exact,
identity-bound loader execution closure. It must demonstrate that broad
`/lib` or `/usr` execute grants are unnecessary and that unregistered
executables remain denied.

