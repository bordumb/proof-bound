# Frozen effect-plan contract

This corpus fixes the Experiment 0012 candidate before implementation. It is a
research model, not a production Proofbound schema or sandbox promise.

## Canonical records

Plans use `proofbound-research-effect-plan/1`. Plan IDs and effect IDs are
lowercase ASCII stable IDs. Effects form a strict lexical set by ID. Paths are
portable project-relative paths: `/`, `\\`, empty, dot, parent, control, and
reserved state components reject. Digests are lowercase `sha256:` identities.

The plan identity is the domain hash `proofbound-research-effect-plan/1` over
canonical JSON. A trace uses `proofbound-research-effect-trace/1`; its identity
is the same-schema domain hash over all fields except `identity`.

All records are closed: unknown fields reject. A successful trace contains
exactly `schema`, `plan_id`, `plan_identity`, `observations`, `dispositions`,
`outputs`, `cache_eligible`, and `identity`. An observation contains a
zero-based `index`, `effect_id`, `kind`, `disposition`, and a typed `value`.
Input and output values are artifact records or explicit absence, execution,
or secret records; no display string substitutes for a typed value.
Dispositions are a strict lexical set by effect ID and contain exactly
`effect_id` plus `observed` or `unused`. Outputs are a strict lexical set by
logical path and contain exact digest and size. Trace identity excludes only
the `identity` member.

## Effects

- `read-file` binds an exact regular-file path, byte digest, size, and Unix
  mode. The non-Unix implementation records a tagged readonly model.
- `require-absent` binds a path whose absence is consumed.
- `write-ephemeral` grants creation only strictly below one fresh runner-owned
  logical root. It grants neither reads nor reviewed-tree writes.
- `write-reviewed` grants one exact update-only path and postimage. Check and
  replay operations reject it before workload entry.
- `read-environment` binds one name and either an exact value digest or
  `secret = true`. A secret trace is never cache-eligible.
- `execute` binds tool bytes, argv, and one boundary: `mediated`, `opaque`, or
  `externally-enforced`. Opaque execution is never cache-eligible. External
  execution requires a separately registered enforcement receipt whose
  identity and effect set match exactly.
- `network`, `clock`, and `random` use `mode = "denied"` in this corpus.
  Attempting them is an effect violation; denial does not fabricate a value.

Every runtime host call consumes exactly one effect declaration. Unused
declarations remain in the trace with disposition `unused`; they are not
silently deleted. Observations are ordered by operation index and bind the
effect ID, kind, exact input or output identity, and disposition.

## Workloads

`hidden-read` reads `fixtures/hidden/policy.txt` through the mediated host and
returns its bytes. The unrelated control is not declared. Its positive trace
identity must change when the policy bytes change and remain stable when only
the unrelated control changes.

`mutation-replay` reads the registered target, complete replacement, and
witness. It writes only `ephemeral/mutation/target.txt`, requires the baseline
to contain `limit=10`, requires the postimage to equal the registered mutant,
and treats the witness text `reject-unbounded` as the typed predicate. It does
not edit the reviewed target.

`distribution-build` reads two registered payload files, requires the output
logical path absent, and writes canonical JSON containing the lexically sorted
path, digest, size, and UTF-8 content of both payloads beneath
`ephemeral/distribution/package.json`. Extra source or output paths reject.

`subprocess-boundary` does not run a native program in this corpus. It checks
whether an execution declaration is honest: an opaque process is
cache-ineligible, and an externally enforced process is eligible only when the
registered synthetic receipt independently binds its tool and allowed effects.
This tests the type boundary, not the effectiveness of an OS sandbox.

## Trace and invalidation

Cache eligibility is derived: all consumed operations must be mediated or
covered by exact external enforcement; no secret, reviewed write, or opaque
process may occur; all bound input identities must match current state.
Invalidation compares typed consumed input/effect identities rather than a
repository revision. A changed consumed node invalidates with a path to its
effect ID; an unrelated node has no path and must not invalidate.

The invalidation decision is a closed
`proofbound-research-effect-invalidation/1` record containing `plan_id`, old
and new trace identities, `invalidated`, and a lexical set of changed effect
IDs. A global-revision field or fallback is not part of the candidate.

## Metric counting

Plan bytes and trace bytes are canonical JSON byte lengths. Declaration count
is the number of effect records. Observation count excludes unused
dispositions; coverage reports observed declarations and all declarations
separately. Workload-body entry is a Boolean test-only counter set immediately
after static plan and requested-effect authorization succeeds.
