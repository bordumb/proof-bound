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

Before committing this section, review the questions, scope, and pass criteria
as one system. Each pass criterion must be internally satisfiable, and criteria
must not contradict one another under the same registered conditions. Criteria
that intentionally cover mutually exclusive outcomes or different runs must
name those conditions explicitly. For mathematical claims, name the quantified
carrier and domain, the equality or projection being used, and the exact
property claimed (for example, a total preorder on concrete values versus a
total order on equivalence classes). Distinguish a finite corpus result from a
universal claim, and give each question a concrete observation that would
falsify it. If a term remains ambiguous, a criterion both requires and forbids
the same observation, or the conditions needed to reconcile criteria are
unstated, the experiment is not ready to register.

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
