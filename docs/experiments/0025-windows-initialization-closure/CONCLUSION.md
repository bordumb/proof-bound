# Experiment 0025 conclusion

[Registration](README.md) · [Machine result](results/execution.json) ·
[Journal](JOURNAL.md) · [Artifacts](ARTIFACTS.md)

- **Decision:** revise
- **Executed / concluded:** 2026-09-04 / 2026-09-04
- **Scope:** GitHub-hosted native Windows 11 ARM64, version `10.0.26200`

## Result

The exact Windows initialization closure repairs EXP-0023's pre-entry
`STATUS_DLL_INIT_FAILED` result. All three registered runtimes reached their
subjects inside a fresh AppContainer with a low-integrity restricted token, a
one-process no-breakaway job, a private desktop, exact staged artifacts and
ACLs, and a root-scoped DOS drive alias. No execution used a fallback.

The overall decision is **revise**. Node and Rust completed all ten repetitions
each with the exact frozen 32-byte output. Python completed all ten processes
with exit status zero but emitted a 33-byte CRLF representation rather than
the registered LF bytes. Exact bytes are part of the frozen cross-language
contract, so those executions are incomplete and cannot be counted or reused.
Q2 fails with 20 of 30 exact positive executions.

Eighteen of 21 authority probes produced definite access or policy denials.
The Python, Node, and Rust network probes all reached the connect operation,
but the registered loopback endpoint refused the connection. Connection
refusal proves neither that the AppContainer policy denied the operation nor
that a reachable endpoint would have been blocked. The validators therefore
classify these three observations as incomplete and non-reusable rather than
turning ambiguous operating-system text into a denial. Q3 fails.

Q1 passes because the registered initialization closure restored entry for all
three runtimes without weakening the sandbox. Q4 passes because all 30
candidate, identity, alias, ACL, token, job, artifact, slot, policy, tree,
freshness, and timing mutations were rejected with their exact registered
codes. Q5 passes because the independent Rust and Python validators emitted
byte-identical reports and attack reports, the reviewed tree was unchanged,
and no denied or incomplete execution became reusable. The complete run took
46,422 ms, below the frozen 60,000 ms ceiling.

## What the experiment establishes

Windows can implement the bounded Proofbound effect contract without a
container or simulated policy. The enforcement boundary is conjunctive rather
than a single `sandboxed` flag: AppContainer identity, restricted token,
integrity level, process job, private desktop, exact executable and DLL
closure, path alias, ACL state, environment, file identity, and post-execution
tree state are all independently represented and checked.

The result also demonstrates why assurance experiments must distinguish a
green executor from a passing hypothesis. The workflow completed correctly by
retaining an adverse decision. Treating exit zero as success would have hidden
both the Python byte mismatch and the inconclusive network observations.

## Boundaries and non-claims

- The tested corpus contains small standalone Python, Node, and Rust programs,
  not package managers, build backends, native extensions, child-process trees,
  interactive applications, or distributed services.
- The initialization closure is exact for the identified GitHub runner and
  registered runtime artifacts. It is not a universal list of Windows loader
  dependencies.
- Security-descriptor and file identities are bound, and live operations test
  the policy, but this experiment does not constitute a verified model of the
  Windows access-check algorithm.
- The Python mismatch is a cross-platform source/output contract defect. It is
  not evidence that Python failed to execute inside the boundary.
- Connection-refused is deliberately not classified as network-policy denial.
  A confirmatory network test needs a registered reachable parent endpoint and
  a separately verified unsandboxed control.
- The GitHub-hosted environment is one Windows 11 ARM64 configuration. The
  result does not establish x86-64 or self-hosted Windows equivalence.

## Next research

Run a newly preregistered successor rather than editing this result. Freeze a
platform-neutral byte-emission contract for all three subjects and a live
network oracle whose reachability is demonstrated immediately outside the
sandbox. Re-run the same positive and authority matrix with those two changes,
retaining the exact initialization closure and all 30 successful adversarial
checks. Only that successor can decide whether Windows joins the bounded macOS
and Linux support already observed.

## Platform references

- Microsoft documents the active-process job limit and its
  `ERROR_NOT_ENOUGH_QUOTA` failure in
  [`JOBOBJECT_BASIC_LIMIT_INFORMATION`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information).
- Microsoft defines Winsock error 10061 as
  [`WSAECONNREFUSED`](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2),
  normally caused by connecting to a service with no listener. That is why the
  experiment does not reinterpret it as an AppContainer access denial.
