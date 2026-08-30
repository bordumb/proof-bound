# Experiment NNNN: <title>

- **Status:** planned | running | concluded | abandoned
- **Registered:** YYYY-MM-DD (commit of this Questions section)
- **Started / concluded:** YYYY-MM-DD / YYYY-MM-DD
- **Subject:** <repo + full commit, or crate + exact version> (pin at start
  if unknown at registration; mark `TBD-at-start` until then)
- **Proofbound:** <commit the experiment runs against>
- **Operator:** <human / agent name>

## Questions (pre-registered)

Three to five falsifiable questions, each with an explicit pass criterion.
Committed before any experiment work begins. Do not edit after work starts —
add follow-up questions in the journal instead.

1. **Q1 —** <question>? Pass: <observable criterion>.
2. **Q2 —** ...

## Scope

- In: <the bounded subset>.
- Out: <explicitly excluded surface, so an abandoned experiment still reads
  honestly>.

## Journal (append-only)

- **YYYY-MM-DD** — <entry. Corrections are new entries, never edits.>

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| F1 | <what happened> | <link/digest> | spec-change (§n, vX) · adr (#n) · case-record · bug (fixed at <commit>) · accepted-limitation |

Every finding with a disposition also gets a row in
[DIVERGENCES.md](DIVERGENCES.md).

## Outcome

Answer each pre-registered question: **pass / fail / unanswered** (unanswered
is a legitimate outcome and stays visible), with one line of justification
each.
