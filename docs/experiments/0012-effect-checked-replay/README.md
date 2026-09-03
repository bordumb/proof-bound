# Experiment 0012: Effect-checked replay

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-005
- **Status:** in progress; preregistration and corpus frozen, not executed
- **Registered:** 2026-09-03
- **Started / concluded:** — / —
- **Subject:** Proofbound `6b32d47884bb07ade225cd322b94b0dadcf58472`
- **Operator:** Codex (GPT-5)

## Why this experiment

EXP-LANG-003 derived precise invalidation inside a closed dependency model but
then falsified the model's execution claim: a real checker read an undeclared
file and retained stale evidence. Binding a repository revision prevented that
retention only by invalidating an unrelated unit and could not explain the
miss through a changed semantic dependency.

An assurance language therefore needs more than declarations. It must either
mediate effects, enforce them at a lower boundary, or admit that a subprocess's
actual authority is wider than its declared inputs. This experiment tests a
small effect-checked replay machine before any production sandbox or language
syntax is selected.

The candidate distinguishes:

1. **mediated operations**, whose file, environment, time, randomness,
   network, secret, process, and write effects pass through a typed host API;
2. **opaque subprocesses**, whose hidden reads and side effects cannot be
   excluded by language-level checking alone; and
3. **externally enforced subprocesses**, which may claim a narrower boundary
   only when an independently named OS/runtime mechanism supplies enforcement
   evidence.

Refusing cache reuse for an opaque subprocess is a valid result. Relabeling it
as closed because its command line names registered files is not.

## Questions (pre-registered)

1. **Q1 — Static effect prevention.** Can typed plans reject forbidden
   authority before expensive work? **Pass:** every registered undeclared
   environment, network, clock, randomness, secret, reviewed-root write,
   symlink escape, lifecycle-script, and unregistered executable request is
   rejected before the workload body runs, with the registered exact code;
   both independent validators agree. **Falsifier:** a forbidden operation
   starts, an alias bypasses the plan, or either implementation accepts a
   different authority set.
2. **Q2 — Mediated trace parity.** Does execution stay within the declared
   effect set? **Pass:** the mutation, distribution, and hidden-read fixtures
   execute only through the candidate host API; every observed operation has
   exactly one authorizing declaration and every consumed declaration has a
   typed trace disposition; undeclared operations fail at the attempted host
   call; Rust and Python derive byte-identical traces. **Falsifier:** an
   observed effect lacks authority, a declared effect disappears without a
   disposition, or traces disagree.
3. **Q3 — Sound and narrow invalidation.** Does enforced mediation repair the
   EXP-LANG-003 falsifier without a global revision? **Pass:** changing the
   hidden input either blocks the undeclared read or changes the bound trace
   identity before reuse; changing the registered unrelated control leaves the
   hidden-reader identity unchanged; no stale reuse and no unrelated
   invalidation occur in ten repetitions. **Falsifier:** the changed hidden
   value reuses evidence, or the unrelated control invalidates the reader.
4. **Q4 — Subprocess honesty.** Can the model prevent a language-level plan
   from overclaiming what it enforces? **Pass:** every ordinary subprocess is
   typed `opaque` and cache-ineligible unless a registered external enforcement
   receipt covers its declared effects; deleting, substituting, weakening, or
   forging that receipt rejects; the report separately names statically
   mediated, externally enforced, and merely observed effects. **Falsifier:**
   command/argument registration alone authorizes exact-read-closure reuse or
   an absent enforcement mechanism is inferred.
5. **Q5 — Representative route feasibility.** Can the bounded effect model
   describe useful mutation and distribution work without granting ambient
   authority? **Pass:** one full-file mutation replay and one deterministic
   package construction fixture complete under exact file/read/write/tool
   plans, preserve the reviewed root, produce registered byte identities, and
   reject all route-specific attacks; the report records declaration and trace
   size. **Falsifier:** either route needs unrestricted filesystem, environment,
   process, or network authority, or the candidate hides route-specific meaning
   in untyped strings.

## Candidate model

```text
EffectPlan {
  schema: "proofbound-research-effect-plan/1"
  workload: MutationReplay | DistributionBuild | HiddenRead
  effects: Set<Effect>
}

Effect =
    ReadFile<Path, Preimage>
  | RequireAbsent<Path>
  | WriteEphemeral<PathBoundary>
  | WriteReviewed<Path, Postimage, UpdateOnly>
  | ReadEnvironment<Name, ValueIdentity | Secret>
  | Execute<ToolIdentity, Argv, ExecutionBoundary>
  | Network<Denied | RegisteredEndpoint>
  | Clock<Denied | RegisteredValue>
  | Random<Denied | RegisteredGenerator>
  | HumanJudgment<RegisteredReview>

ExecutionBoundary = Mediated | Opaque | ExternallyEnforced<ReceiptIdentity>

EffectTrace {
  plan_identity: Sha256
  operations: Ordered<ObservedEffect>
  unused_declarations: Set<EffectId>
  cache_eligible: Bool  // derived, never authored
  identity: Sha256
}
```

Paths are normalized project-relative paths. Exact reads bind path, file type,
bytes, and relevant permissions. Absence is a first-class preimage. Ephemeral
writes must remain inside a fresh runner-owned root. Reviewed writes are valid
only for an explicit update operation and exact postimage. Environment values
are identity-bound unless secret; secret reads make the trace non-reusable.
Denied network, clock, and randomness are unavailable capabilities, not values
silently supplied by the host.

The generic kernel knows effect kinds but not Cargo, Python packaging, or
mutation semantics. Typed workload records connect route-specific roles to
effect IDs; adapters cannot introduce new generic effect variants.

## Registered subjects

- the retained EXP-LANG-003 undeclared-read falsifier and unrelated control;
- one bounded full-file mutation replay derived from the allowance demo;
- one bounded deterministic archive construction derived from the Python
  inventory demo; and
- ordinary-subprocess and synthetic external-enforcement controls.

The corpus commit will freeze small standalone fixtures rather than execute the
full production adapters. This isolates the effect boundary from unrelated
tool installation and keeps the experiment's authority auditable.

## Registered measurements

- `M-FX-001`: forbidden operations rejected before workload-body entry;
- `M-FX-002`: observed operations with exactly one declaration / operations;
- `M-FX-003`: declarations with an observed or unused disposition / declarations;
- `M-FX-004`: stale-cache acceptance count;
- `M-FX-005`: unrelated invalidation count;
- `M-FX-006`: Rust/Python canonical trace disagreement count;
- `M-FX-007`: opaque subprocesses incorrectly marked cache-eligible;
- `M-FX-008`: plan, trace, and declaration bytes per workload; and
- `M-FX-009`: route completions with exact output identities / 2.

Finite corpus targets are zero for M-FX-001's accepted attacks, M-FX-004,
M-FX-005, M-FX-006, and M-FX-007. These are corpus results, not a universal OS
sandbox claim.

## Registered attacks

The machine preregistration fixes exact codes for undeclared reads,
environment, network, clock, randomness, secret access, reviewed and ephemeral
write escapes, symlink substitution, lifecycle execution, executable and argv
substitution, missing/forged/weakened external enforcement, hidden subprocess
reads, effect aliases, duplicate declarations, unbound observations, omitted
unused dispositions, mutation postimage drift, package extra paths, and global
revision over-invalidation.

## Scope

- **In:** the three bounded workloads; typed plan and trace; mediated host API;
  exact file and absence identities; environment/process/effect authority;
  opaque-subprocess classification; synthetic externally enforced receipt;
  Rust/Python independent validators; deterministic replay and invalidation.
- **Out:** claiming that the current Proofbound adapters are sandboxed;
  production cache changes; arbitrary native processes; kernel or container
  sandbox implementation; Windows/Linux/macOS parity; performance benchmark;
  network namespace construction; production schema adoption.

## Procedure

1. Commit this preregistration before fixtures or implementation.
2. Freeze workloads, effect plans, expected identities, attacks, and metric
   algorithms in a separate corpus commit.
3. Implement the typed plan validator, mediated runner, trace derivation, and
   invalidation decision in Rust.
4. Implement the validator and trace derivation independently in Python.
5. Run every positive workload ten times, execute all attacks, and retain the
   canonical report.
6. Conclude Q1–Q5 separately. Do not claim OS-level enforcement from the
   mediated research interpreter.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0012-F001 | Reserved for execution. | — | pending |

## Outcome

Q1–Q5 are unanswered. The effect-plan corpus is frozen; neither independent
implementation has executed it yet.
