# Experiment 0020 conclusion

Experiment 0020 concludes **unanswered**. The backend-neutral effect contract
compiled to a bounded Linux policy, and both independent validators agreed,
but the available Linux environment did not expose the registered Landlock
mechanism. No workload was executed and no substitute evidence was admitted.

## Result

The retained environment was a real Linux arm64 VM running kernel
`6.12.54-linuxkit`. The registered native launcher queried the Landlock ABI
with `landlock_create_ruleset(..., LANDLOCK_CREATE_RULESET_VERSION)` and
received `ENOSYS` (`Function not implemented`, exit 125). Repeating the probe
with Docker's outer seccomp profile disabled produced the same result. This is
evidence that the available VM is unsupported, not evidence that Landlock is
absent from Linux generally.

The executor then stopped. It emitted zero positive receipts and zero denial
receipts, did not set `no_new_privs`, did not install its seccomp filter, and
did not count Docker confinement as the registered mechanism. The copied
reviewed tree remained byte- and mode-identical.

Independently implemented Rust and Python validators compiled nine authority
classes to explicit Linux dispositions and produced byte-identical 3,910-byte
reports. They reject all 16 registered platform, mechanism, fallback, and
integrity attacks exactly. The result remains below the registered
implementation and report limits.

## Interpretation

The design remains plausible but unvalidated in live use. Landlock naturally
expresses exact project reads, runtime execution, and ephemeral write roots;
`clearenv` plus a registered environment rebuild covers process environment;
and seccomp-BPF can deny the bounded network syscall set. That mapping is a
policy-compilation result only.

The experiment found a practical deployment constraint: a modern kernel
version string does not establish that Landlock is enabled or reachable from
the execution environment. Proofbound must probe the exact ABI before cache
lookup and fail closed if it cannot install every registered mechanism.
Container isolation, a read-only mount, or an unconfined subprocess cannot be
used as fallback evidence.

## Next evidence

A confirmatory Linux run needs a native or virtual Linux host where the exact
launcher reports Landlock ABI 4 or newer. That run must execute the frozen
30-positive/21-probe corpus and retain the same independent reports. The
current unanswered result must remain in the record rather than being replaced
or described as a pass.

Experiment 0021 can proceed independently: it tests whether Windows can express
the same authority contract and must apply the same no-fallback rule.
