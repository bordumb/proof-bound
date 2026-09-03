# Experiment 0010: Source-retained invalidation precision

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-003
- **Status:** planned; preregistered, not executed
- **Registered:** 2026-09-03
- **Started / concluded:** — / —
- **Subject:** Proofbound `74fada0ddb077f11b97b99fa10b73dce651c5329`;
  external holdouts are pinned in the machine preregistration
- **Proofbound:** `74fada0ddb077f11b97b99fa10b73dce651c5329`
- **Operator:** Codex (GPT-5)

## Why this experiment

EXP-LANG-001 closed fifteen of sixteen Assurance IR information classes. The
remaining failure is not cosmetic: a portable receipt retains an opaque cache
key and, on reuse, a prior receipt identity, but not the dependency facts that
made reuse sound. A verifier can confirm what the producer said happened; it
cannot reconstruct why an input change should or should not invalidate that
evidence.

This experiment tests a source-retained dependency projection. It distinguishes
semantic and execution dependencies from presentation-only inputs, retains
negative resolution and execution metadata rather than hashing them away, and
derives invalidation explanations through evidence to affected claims.

## Questions (pre-registered)

1. **Q1 — Dependency completeness.** Can one closed dependency model retain
   every cache-relevant fact consumed by the fourteen registered route shapes?
   **Pass:** for all fifteen controlled evidence units and both external
   holdouts, every registered execution-relevant mutation either changes the
   canonical dependency projection and predicted cache identity or fails
   closed before reuse. A forced fresh execution agrees with every prediction,
   and stale evidence is never retained. **Falsifier:** any changed source,
   transitive input, permission, lock, tool, environment value, resolution
   candidate, configuration, generated baseline, or external contract can
   change execution while leaving reusable evidence valid.
2. **Q2 — Invalidation precision.** Can dependency-derived invalidation avoid
   repository-wide reruns without missing affected evidence? **Pass:** every
   scenario's predicted invalidated-unit set exactly equals its
   source-authoritative ground-truth set, frozen in the corpus before the
   implementation; presentation-only and unrelated-language controls
   invalidate no technical evidence; every leaf scenario invalidates a strict
   nonempty subset of its project. Report M-INV-001 and M-INV-002 per change
   class. **Falsifier:** false retention, any extra invalidation in an exact
   controlled scenario, or a leaf change invalidating the entire project.
3. **Q3 — Canonical independent interpretation.** Can independent Rust and
   Python implementations assign one meaning to the projection? **Pass:** both
   implementations produce byte-identical canonical projections, projection
   identities, predicted invalidation sets, and explanation paths for every
   positive case and reject every registered attack with its exact code.
   **Falsifier:** any disagreement, accepted ambiguous encoding, or backend-name
   conditional in generic invalidation logic.
4. **Q4 — Actionable explanation.** Can every invalidation identify a concrete
   changed fact and claim consequence without turning all dependency drift into
   notifications? **Pass:** 100% of invalidated units have a canonical path
   `changed dependency → evidence unit → claim`; irrelevant changes and changed
   facts not consumed by a rule produce no claim notification. **Falsifier:** a
   generic “cache miss” without the changed fact, a notification with no
   affected claim, or suppression of a publication-relevant consequence.
5. **Q5 — Honest migration.** Can source-retained projections be introduced
   without assigning new meaning to old cache keys? **Pass:** the research
   model represents older records as `legacy-opaque-cache`, which is never
   independently reusable; complete records use a distinct versioned
   constructor; no existing Proofbound schema ID is redefined. **Falsifier:**
   migration treats an old key as a dependency list, silently blesses reuse, or
   changes a historical receipt.

## Registered corpus

The controlled corpus has fifteen units spanning fourteen route shapes:

- Python: exact pytest, seeded Hypothesis, mypy, mutation replay, wheel
  reproduction, and independent checking;
- TypeScript: exact Vitest and sampled fast-check under the shared Vitest route,
  `tsc`, mutation replay, and npm package reproduction;
- Rust/Lean: exact Cargo tests, Rust mutation replay, Kani, and Lean theorem
  checking.

The holdouts are Click at upstream commit
`36baa15ff831b939a22bc527cd76ce653ef6f66d` and Vitest Coverage Report Action
at `c4bbc33a89b7ace0e63d35f1f7d4bcee31155a73`. Their local Proofbound
instrumentation and complete tree identities must be captured before execution;
neither holdout may be used to redesign the model after its result is known.

## Candidate model under test

```text
DependencyProjection {
  schema: "proofbound-ir-dependency-projection/1"
  unit: UnitId
  route: RouteClass
  source_revision: RevisionIdentity
  nodes: Set<DependencyNode>
  uses: Set<DependencyUse>
  identity: Sha256
}

DependencyNode =
    Artifact(path, sha256, size, permissions)
  | Resolution(selector, Set<PathState<Artifact | Absent>>)
  | Environment(name, Absent | ValueDigest | SecretPresentNoReuse)
  | Tool(role, executable_identity, version_identity)
  | Contract(role, schema, identity)
  | Platform(os, architecture)

DependencyUse {
  node: DependencyNodeId
  role: Semantic | Execution | GeneratedBaseline | ExternalContract
  purpose: BoundedText
}

InvalidationTrace {
  changed_nodes: Set<DependencyNodeId>
  invalidated_units: Set<UnitId>
  affected_claims: Set<ClaimId>
  paths: Set<DependencyNodeId → UnitId → ClaimId>
}
```

The projection retains typed dependency values. Its identity is a check over
that meaning, never a substitute for it. Presentation dependencies live in the
programme graph but are excluded from technical execution roots unless a route
explicitly consumes them.

## Registered change classes

1. direct semantic source bytes;
2. transitive source outside the immediate package;
3. same-byte executable permission change;
4. package or toolchain lock change;
5. tool executable or reported identity change;
6. absent-to-present competing resolution candidate;
7. allowed environment value or absence change;
8. operation manifest or analyzer/compiler configuration change;
9. generated baseline or committed reproducibility artifact change;
10. external checker or bridge contract change;
11. presentation-only bytes; and
12. an unrelated sibling-language source.

Each of the fourteen route shapes must exercise at least one load-bearing
class. Classes 1–10 must each appear at least once. Classes 11 and 12 are
negative controls and must not invalidate technical evidence.

## Registered attacks

The machine preregistration fixes fifteen attacks covering omission, role and
same-cardinality substitution, stale identity, byte and permission changes,
negative resolution, environment state, tool identity, duplicate/alias
encoding, noncanonical order, over-invalidation, claim/unit rebinding, opaque
digest substitution, secret-bearing reuse, and path escape.

## Measurements and decision rule

- M-SOUND-002 stale retention: target zero.
- M-SOUND-003 independent disagreement: target zero.
- M-INV-001 precision: report per scenario; controlled exact scenarios target
  `1.0`.
- M-INV-002 reduction: report per scenario; every leaf scenario must avoid at
  least one otherwise runnable unit.
- Explanation coverage: target 100% for invalidated units.

All five questions are decided separately. Q1 or Q3 failure blocks any revised
Assurance IR freeze. Q2 failure rejects the precision claim but does not permit
weakening Q1. Q4 failure blocks use of the model for notification routing. A
missing tool or unexecuted required route leaves the affected question
unanswered, never passed.

## Scope

- **In:** the registered controlled units and two external holdouts; exact
  files, modes, absence states, environment identities, tools, contracts,
  dependency uses, invalidation traces, cache predictions, and forced-fresh
  comparison; research-only Rust and independently written Python validators.
- **Out:** production wire adoption; distributed caches; remote execution;
  kernel-enforced sandboxing; arbitrary build systems; performance claims
  beyond the registered corpus; final DSL syntax.

## Procedure

1. Commit this preregistration before implementing the candidate.
2. Capture the exact controlled and external source trees, current cache
   observations, and scenario ground truth without copying dependency
   directories into Git. Commit that corpus before implementation.
3. Build role-typed projections from source-retained inputs, not cache keys.
4. Implement canonical validation and invalidation independently in Rust and
   Python.
5. Execute all positive scenarios, controls, and attacks.
6. For each load-bearing change, compare prediction with a forced fresh run.
7. Record precision, reduction, stale retention, disagreement, and explanation
   coverage by route and change class.
8. Conclude every question without editing this registration.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0010-F001 | Reserved for execution. | — | pending |

## Outcome

Q1–Q5 are unanswered. No experiment execution has started.
