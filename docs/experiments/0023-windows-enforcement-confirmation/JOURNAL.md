# EXP-0023 journal

## 2026-09-03 — native host qualification

GitHub Actions provided a native Windows 11 ARM64 runner (`10.0.26200`). The
host probe created and deleted a fresh AppContainer profile and exercised the
restricted-token, low-integrity, and one-process-job APIs. No compatibility
layer, Windows Server runner, container, or simulation was used.

## 2026-09-03 — fail-closed process-entry investigation

The first smoke used `whoami.exe` and exposed two implementation defects before
the experiment could be interpreted: PowerShell allowed a later JSON display
command to mask the probe's nonzero exit, and the child token still had the
Administrators SID enabled. The workflow now retains the probe exit separately,
and the launcher constructs a restricted LUA token and inspects the actual
suspended child token before resume.

The corrected child token met the registered token and ordering constraints but
the process exited `0xc0000142` before user code. Two bounded falsifier checks
failed to repair it: an AppContainer-specific private window station/desktop,
and staging the signed executable in AppContainer-owned profile storage. These
checks narrow the missing premise without weakening any registered layer.

## 2026-09-03 — decision

[Run 33814855635](https://github.com/bordumb/proof-bound/actions/runs/33814855635)
completed the decision pipeline and retained the exact host, child-process, and
derived execution receipts. The preregistered result is `revise`; no workload or
authority-probe receipt was created.
