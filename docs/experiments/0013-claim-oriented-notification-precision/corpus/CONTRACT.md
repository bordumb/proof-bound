# Frozen notification contract

This contract fixes the Experiment 0013 machine comparison before either
implementation. It is a finite oracle benchmark, not evidence about human
behavior.

## Input records

`scenarios.json` uses `proofbound-research-notification-corpus/1`. Scenario IDs
are unique in the frozen fixture order. Claim, fact, finding, and path IDs are
nonempty stable ASCII IDs and form strict lexical sets within their scopes. All
records are closed. Engines sort derived cross-scenario output explicitly.

An uncertainty fact contains exactly:

- `id`;
- one `kind`: `assumption`, `exclusion`, `uncertainty`, `contradiction`,
  `stale-evidence`, or `missing-evidence`;
- nonempty `owner` and `scope`;
- required-nullable RFC 3339 `expires_at`;
- a typed `consequence`: `may-weaken`, `does-not-strengthen`, or
  `blocks-publication`; and
- a lexical unique evidence-identity set. Contradictions require at least two
  evidence identities. Stale evidence requires exactly one. Missing evidence
  requires none. No fact kind is assurance evidence or a numeric confidence
  score.

Every raw finding names one fact and retains its tool, code, and severity.
Severities are `low`, `medium`, `high`, or `critical`; they do not determine
claim relevance. Every impact path names one finding, its fact, a known claim,
a nonempty ordered dependency-node path, whether the path is consumed, a
requested action, and one publication consequence: `block`, `warn`, or `none`.
The finding-to-fact join must agree exactly.

## Baseline and candidate

The tool-oriented baseline emits one interrupting alert per finding. It does
not delete findings, group them, or infer claim impact.

The candidate groups consumed impact paths by this exact tuple:

```text
(scenario, claim, fact kind, requested action, publication consequence)
```

One `proofbound-research-notification/1` record is emitted per group. It
contains a domain-hashed identity, the tuple fields, the lexical unique finding
IDs, and the full impact paths sorted by path ID. Paths with different actions
or publication consequences never merge. Severity is retained in the source
finding graph but is not a grouping or suppression input.

A finding absent from all consumed paths becomes exactly one non-interrupting
graph update with reason `no-consumed-claim-path`. The union of notification
finding IDs and graph-update finding IDs must equal the complete input finding
set with no overlap. Candidate report identity uses domain
`proofbound-research-notification-report/1` over canonical JSON excluding only
the `identity` field.

## Oracle and metrics

`oracle.json` is not an engine input. The executor uses it after both reports
exist. A critical action is an exact tuple of scenario, claim, fact kind,
requested action, and `publication_consequence = "block"`.

Critical recall is the number of oracle tuples represented by an interface
divided by the oracle count. A baseline alert represents a critical tuple when
its finding has the registered consumed path. A candidate notification
represents its own grouping tuple. False escalation counts interrupting records
whose findings have no consumed claim path. Volume is the number of
interrupting records; graph updates are retained but not interruptions.

All counts are integers. The preregistered 50% volume threshold is compared as
`2 * candidate_notifications <= baseline_alerts`, without floating point.

## Human instrument

`instrument.json` freezes a counterbalanced task shape but contains no answers
or participant observations. Human metrics exist only if at least 12 eligible,
consenting people complete it. An agent run, oracle replay, or generated answer
must not be counted as a participant.
