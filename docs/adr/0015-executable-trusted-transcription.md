# ADR 0015: Make trusted transcription executable and derived

Status: accepted

## Context

Experiment 0001 found a real evidence shape in Matrix Math's rank track: a
program decoded source bytes into typed Lean literals and a programmatic
re-encoder checked the external byte round trip. Specification 0001 had named
that shape `trusted-transcription` since version 0.4, but Proofbound v0.5 had no
manifest or adapter route that could materialize it. A generic checker could
run, but it could not honestly create the transcriber and re-encoder TCB nodes
or the `TRANSCRIBED` linkage. The experiment therefore failed Q3 rather than
forking the framework or relabeling test evidence.

A new route must also avoid the binding hole fixed for artifact soundness. An
adapter-authored `round_trip_passed = true` would merely move the same trust
mistake to a different evidence kind. Running the re-encoder against the
committed transcription would create a second problem: a generated candidate
could match the committed file while an unrelated committed-file round trip
passes. The two checks must share the same freshly generated candidate.

## Decision

- Reserve `proofbound-evidence-unit/2` for a strict
  `trusted-transcription`/`transcription` route. Existing evidence units remain
  `/1`; they are not mass-migrated or silently reinterpreted.
- Require a typed `proofbound-trusted-transcription/1` manifest block naming
  the exact source, committed transcription, Python driver, two versioned
  format IDs, and fixed `proofbound-transcription-driver/1` ABI. The exact
  sorted inputs are those three paths; the exact inventory is the source and
  committed transcription; committed outputs and free-form operation fields
  are forbidden. The environment allowlist is exactly `PATH`, whose value is
  hashed and bound while the resolved Python executable identity is recorded;
  no other parent environment is admitted.
- Run `transcribe` first, compare its fresh candidate byte-for-byte with the
  committed transcription, then pass that same candidate to `reencode` and
  compare the result byte-for-byte with the source.
- Carry source, committed transcription, candidate, re-encoding, and driver
  artifact identities across the observation and canonical evidence record.
  Do not carry a checker-authored success Boolean.
- Derive distinct transcriber and re-encoder role identities from the fixed
  ABI, exact driver identity, and role under the
  `proofbound-transcription-tcb-role/1` domain. Derive their TCB nodes in the
  compiler as `tcb:trusted-transcription:<unit-id>:transcriber` and
  `tcb:trusted-transcription:<unit-id>:reencoder`, with corresponding ledger
  names `trusted-transcription/<unit-id>/transcriber` and
  `trusted-transcription/<unit-id>/reencoder`, fixed-ABI versions, and role-
  digest identities. The independent verifier recomputes the identities;
  manifests and adapters cannot author TCB node IDs.
- Add the immutable Tier 1 `transcribed` profile. It requires valid trusted-
  transcription evidence and `TRANSCRIBED` linkage, but no theorem. It never
  admits that evidence as proof, artifact binding, or source refinement.
- Retain the outer canonical evidence, compiled release, and release envelope
  at version 2. The nested record and the evidence-unit registration are the
  only new wire versions required.

## Rejected alternatives

- Treating a generic test/checker exit status as transcription evidence leaves
  both byte comparisons and the TCB roles implicit.
- Accepting a manifest Boolean for either comparison delegates the central
  honesty decision to the component being audited.
- Re-encoding the committed transcription instead of the fresh candidate
  permits two disconnected successful checks.
- Reusing one TCB node because one file implements both operations hides the
  distinct ways that file is trusted.
- Calling the result artifact-bound would claim a theorem-to-byte connection
  that this route intentionally does not establish.

## Consequences

Experiment 0001's Q3 remains an honest historical failure at its pinned v0.5
tooling, while EXP-0001-D03 is fixed as product work in version 0.9. Projects
can now register that evidence shape without core forks and receive the
deliberately weaker `TRANSCRIBED` facet. The manifest is somewhat repetitive,
but its exact input and inventory sets close omission and argument-smuggling
paths. The Python driver and interpreter stay in the visible trust boundary;
the route does not make their parsing semantics formally verified.
