# Q1 completion capture revision 1

[Preregistration](../../q1-completion-preregistration.json) ·
[Execution plan](../../q1-completion-plan.md) · [Capture index](index.json)

- **Status:** captured; analysis and attacks not yet executed
- **Subject:** `f3a5362fda0bcdfc444bd9f9db06e94b84ae1784`
- **Cases:** Python, TypeScript, and Rust

Each language directory contains the exact compiled receipt, release envelope,
and TCB ledger emitted during the registered run. The [index](index.json)
binds their raw file identities, semantic payload identities, environment,
selected statuses, execution preconditions, cache observations, and independent
verifier verdicts.

These directories are intentionally semantic captures, not redistributed
portable releases. Native binaries, duplicate public schemas, auxiliary sealed
files, dependency directories, and private caches were excluded according to
the preregistered storage rule. The standalone verifier passed against each
complete temporary release before that pruning; it is expected to reject the
committed subset as incomplete if invoked as a release directory.

No success decision follows from capture alone. Matrix revision 3 remains the
current Q1 result until both independent implementations derive exact traces
and the preregistered artifact and cache attacks have run.
