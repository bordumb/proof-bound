# Experiment 0021 conclusion

Experiment 0021 concludes **unanswered**. Independent Rust and Python
implementations compile the frozen effect contract to the same bounded Windows
candidate, but no supported Windows 11 environment was available. The host
gate emitted zero workload receipts and did not simulate or substitute a
weaker boundary.

## Result

The effective policy uses four mechanisms together rather than treating any
one as sufficient:

- a fresh AppContainer profile with no network capabilities;
- a low-integrity restricted token with maximum privileges disabled and
  administrator SIDs deny-only;
- a non-breakaway job object with kill-on-close and an active-process limit of
  one; and
- explicit access entries for the runtime, source, input, reviewed tree, and
  fresh ephemeral root.

Absence and permission identities remain pre-execution checks. The runtime and
Windows loader boundary remains a separately registered premise. The candidate
also requires reparse-point rejection; path strings and ACLs alone are not an
identity boundary.

Both implementations produced byte-identical 3,986-byte reports. Their
compiled policy contains five exact path-authority rows and rejects all 18
registered capture, target, AppContainer, token, job, ACL, environment,
executable, fallback, and identity attacks exactly. Both implementations stay
well below their registered size ceilings.

## Interpretation

This result establishes a concrete policy design, not Windows enforcement.
The four mechanisms are deliberately conjunctive: AppContainer capabilities
constrain network and named-object authority, the token removes ambient user
privileges, the job constrains process escape, and ACLs grant exact filesystem
access on a fresh copy. Omitting any layer changes the effective authority.

The result also identifies Windows-specific premises that the common effect
contract must expose without embedding Windows terminology in its semantic
core: runtime-loader closure, NTFS access-check behavior, reparse-point
handling, AppContainer profile identity, and job assignment before user code.

## Next evidence

A confirmatory run needs Windows 11 on arm64 or x86_64 and an independently
identified native launcher implementing the compiled policy. It must execute
the frozen 30-positive/21-probe corpus, retain raw process outcomes, prove the
reviewed tree unchanged, and reproduce the same independent report. Until
then, Windows parity and production cache authority remain open.
