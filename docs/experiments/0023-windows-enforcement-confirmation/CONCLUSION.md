# EXP-0023 conclusion

EXP-0023 is concluded with decision **revise**.

The GitHub `windows-11-arm` host is genuine Windows 11 ARM64 and exposes the
registered AppContainer, restricted-token, job-object, and ACL APIs. The live
launcher proved the most important ordering invariant: it created the process
suspended, assigned it to the one-process job, inspected the actual child token,
and only then resumed it. The inspected token contained the fresh AppContainer
SID, low-integrity SID `S-1-16-4096`, and deny-only Administrators SID.

The candidate did not reach user code. A staged signed `cmd.exe /d /c exit 0`
terminated with `0xc0000142` (`STATUS_DLL_INIT_FAILED`) after resume. Moving the
application into AppContainer-owned storage and creating a private ACL-bound
window station and desktop did not change that result. This localizes the
remaining premise to Windows process initialization—particularly the executable,
DLL, object-manager, registry/profile, or related loader closure—not to host
availability, token construction, job ordering, or the shared desktop.

The result is not a passing enforcement claim:

- Q1 failed because the complete runnable boundary was not established.
- Q2 failed because zero of 30 positive workloads entered user code.
- Q3 failed because the 21 denial probes could not run; the fail-closed gate did,
  however, emit no reusable evidence.
- Q4 failed because there was no workload capture for independent validators.
- Q5 failed because the runtime/DLL initialization closure remains unregistered.

This is `revise`, rather than `unanswered`, because the eligible native host and
core boundary mechanisms were exercised and a bounded criterion failed. It is
not `stop`: no fallback ran, no denied execution became reusable, and the
reviewed tree was not used as an execution tree.

The next Windows experiment must preregister and independently enumerate the
minimum native initialization closure before rerunning the frozen corpus. It
must not obtain a green result by enabling Administrators, raising integrity,
removing AppContainer, allowing breakaway, or granting broad ambient filesystem
authority.
