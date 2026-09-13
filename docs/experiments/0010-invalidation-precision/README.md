# Experiment 0010: Source-retained invalidation precision

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-003
- **Status:** concluded; candidate rejected
- **Registered:** 2026-09-03
- **Started / concluded:** 2026-09-03 / 2026-09-03
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
| EXP-0010-F001 | The source-derived model exactly predicted all 26 frozen scenarios: 57 invalidated-unit events, no stale retention, no extra invalidation, and 57/57 concrete explanation paths. | `results/execution.json`; independent Rust validation | Supports the typed dependency constructors within the closed model, but is not evidence that the model captures all dependencies consumed by real tools. |
| EXP-0010-F002 | A checker can read an undeclared file. Holding the registered projection fixed then permits stale reuse; including the Git revision prevents that reuse but also changes an unrelated unit's identity. | `results/revision-falsifier.json` | Falsifies the candidate's joint soundness-and-precision claim. Dependency declarations require an enforced or independently observed read/effect boundary. |
| EXP-0010-F003 | Thirteen of fourteen controlled route shapes had runnable fresh baselines. The registered Lean theorem route remained unanswered, and the frozen Vitest holdout discovered 161 tests against six registered tests. | `results/forced-fresh-smoke.json` | The required route-by-change forced-fresh matrix is incomplete and cannot strengthen the model result into a production cache claim. The holdout mismatch is retained rather than repaired after observation. |
| EXP-0010-F004 | Rust and Python independently validate, invalidate, and canonicalize registered projections and attacks, but only the Python implementation derives projections from source manifests. | implementation and focused test corpus | Fails Q3's stronger requirement that both implementations independently produce every positive projection. Shared canonical bytes do not substitute for independent extraction. |
| EXP-0010-F005 | A global revision-induced miss has no typed changed dependency, while ignoring the revision can retain evidence after an undeclared read changes behavior. | `results/revision-falsifier.json` | Falsifies Q4 for the candidate. Actionable notifications require captured effects, not generic revision drift. |

## Outcome

| Question | Result | Reason |
|---|---|---|
| Q1 — Dependency completeness | **Fail** | The executable revision falsifier changes checker behavior through an undeclared read while a fixed declared projection remains reusable. A global revision avoids retention only by ceasing to be a complete, typed account of the consumed dependency. |
| Q2 — Invalidation precision | **Fail** | A global revision change invalidates both the consuming unit and an unrelated unit, violating the exact-set and negative-control criteria. |
| Q3 — Canonical independent interpretation | **Fail** | Rust and Python agree on validation and canonical model vectors, but the preregistration required both to produce every positive projection; source extraction exists only in Python. |
| Q4 — Actionable explanation | **Fail** | Global revision drift produces a cache miss without a concrete changed-dependency path. Ignoring it recreates stale retention. Model-only 57/57 explanation coverage does not satisfy the executable falsifier. |
| Q5 — Honest migration | **Pass** | Complete projections use new research schema IDs, and legacy opaque cache records are never independently reusable. No historical Proofbound wire identifier was reinterpreted. |

The candidate is rejected and Assurance IR `/1` remains unfrozen. The closed
model demonstrates that typed dependency nodes can explain known changes, but
the executable falsifier shows that declarations alone cannot establish that
the list is complete. EXP-LANG-005 must test an enforceable effect boundary;
EXP-LANG-004 may proceed in dependency order, but its frontend-equivalence
claim must not assume that dependency declarations are authoritative merely
because their canonical bytes agree.
