# Experiment 0013: Claim-oriented notification precision

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-006
- **Status:** in progress; preregistration and corpus frozen, not executed
- **Registered:** 2026-09-03
- **Started / concluded:** — / —
- **Subject:** Proofbound `2055e90b221ca6344780b2b60866a91b0db8220f`
- **Operator:** Codex (GPT-5)

## Why this experiment

Tooling for vulnerabilities, quality, reliability, and service levels often
emits one alert per detector finding. Engineers must then reconstruct which
claims depend on it, whether the observation is stale or contradictory, what
decision is required, and whether publication or operation is actually
affected. High volume without impact semantics creates notification fatigue;
simply suppressing weak findings risks hiding the one weak signal that is
load-bearing.

Proofbound's language hypothesis is different: make assumptions, exclusions,
uncertainties, contradictions, stale observations, and missing evidence typed
graph objects, then notify on changes to claim justification. Findings without
a path to a consumed claim remain inspectable graph updates rather than
interruptions. Severity does not override a real dependency path.

This experiment first tests that mechanism against a frozen scenario oracle.
It measures consequence recall, false escalation, notification count, typed
explanations, and independent implementation agreement. These are structural
proxies, not measurements of human comprehension or response time. An optional
participant phase has a separate criterion and cannot be invented if no
participants are available.

## Questions (pre-registered)

1. **Q1 — Typed uncertainty preservation.** Can the candidate preserve the six
   registered states without coercing assumptions or exclusions into evidence?
   **Pass:** Rust and Python classify every oracle fact as exactly one of
   `assumption`, `exclusion`, `uncertainty`, `contradiction`, `stale-evidence`,
   or `missing-evidence`; every category-specific attack rejects with its exact
   code. **Falsifier:** a fact has zero or multiple kinds, a non-evidence state
   strengthens assurance, or the implementations disagree.
2. **Q2 — Critical-consequence recall.** Can claim-oriented grouping preserve
   all publication-impacting consequences even when the originating finding
   has low tool severity? **Pass:** candidate and baseline recall are both
   100% against the frozen critical-action oracle in ten repetitions, including
   every registered low-severity critical case. **Falsifier:** any oracle
   critical action is absent or attached to the wrong claim.
3. **Q3 — Fatigue proxies.** Does claim-oriented reporting reduce irrelevant
   escalation without a global severity suppression rule? **Pass:** candidate
   notifications are at most 50% of baseline finding alerts, candidate false
   escalation is zero, baseline false escalation is nonzero, and unrelated
   findings remain available as typed graph updates in ten repetitions.
   **Falsifier:** an unrelated finding interrupts, a relevant finding vanishes,
   or the threshold is missed.
4. **Q4 — Actionable deterministic output.** Can two independent engines emit
   the same complete decision interface? **Pass:** canonical candidate reports
   are byte-identical; every notification names affected claim, exact
   dependency path, uncertainty kind, requested action, publication
   consequence, and grouped finding identities; all registered integrity and
   grouping attacks reject exactly. **Falsifier:** a required field is inferred
   from display text, distinct actions are merged, ordering changes bytes, or
   either engine accepts an attack.
5. **Q5 — Human product value.** Do practitioners assess impact faster with no
   increase in missed critical consequences? **Pass:** if a participant phase
   occurs, at least 12 consenting participants spanning developer, security,
   release, or audit roles complete counterbalanced baseline/candidate tasks;
   candidate median correct-impact time is lower and missed critical
   consequence rate is no higher. **Falsifier:** either outcome reverses.
   **Unanswered condition:** fewer than 12 eligible participants complete the
   preregistered instrument; structural proxy results must not be presented as
   human evidence.

## Candidate model

```text
UncertaintyFact {
  id, kind, owner, scope, expiry, consequence, evidence
}

ImpactPath {
  finding -> fact -> dependency nodes -> claim
  consumed, requested_action, publication_consequence
}

DecisionNotification {
  claim, kind, paths, findings, requested_action,
  publication_consequence
}
```

The baseline emits one interrupting alert per tool finding. The candidate emits
one notification per distinct claim/kind/action/publication decision and
retains all other findings as non-interrupting graph updates. A low severity is
never a reason to remove a consumed path. Candidate grouping is a canonical set
operation, not a language- or tool-specific heuristic.

## Registered measurements

- `M-UQ-001`: critical oracle actions presented / critical oracle actions;
- `M-UQ-002`: unrelated interrupting notifications / unrelated findings;
- `M-UQ-003`: candidate notification count / baseline alert count;
- `M-UQ-004`: notifications with complete claim/path/kind/action/publication
  fields / candidate notifications;
- `M-UQ-005`: findings retained as notifications or graph updates / findings;
- `M-UQ-006`: Rust/Python canonical report disagreements;
- `M-UQ-007`: exact attack rejections / registered attacks;
- `M-UX-001`: correct impact-assessment time, only if Q5 executes; and
- `M-UX-002`: missed critical consequences, separately for machine oracle and
  human participants.

## Scope

- **In:** a bounded synthetic but role-realistic scenario corpus; six typed
  uncertainty states; tool-alert baseline; claim-oriented grouping; exact
  dependency paths; publication/action oracle; independent Rust/Python
  implementations; ten deterministic repetitions; optional consented study.
- **Out:** production notification delivery; paging policy; organization-wide
  alert economics; learned ranking; severity calibration; claiming that
  structural metrics predict human behavior; recruiting or simulating people.

## Procedure

1. Commit this preregistration before scenarios, oracle, implementation, or
   instrument answers.
2. Freeze scenario facts, raw findings, dependency paths, oracle actions,
   grouping rules, attack mutations, thresholds, and an optional human
   instrument in a separate corpus commit.
3. Implement the candidate independently in Rust and Python.
4. Execute both interfaces ten times, all attacks, and the machine oracle.
5. Run Q5 only if 12 eligible consenting participants are independently
   available; otherwise record it unanswered without synthetic responses.
6. Retain results and conclude each question separately.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0013-F001 | Reserved for execution. | — | pending |

## Outcome

Q1–Q5 are unanswered. The scenario, oracle, attack, threshold, and
response-free instrument corpus is frozen; no implementation or participant
data exists yet.
