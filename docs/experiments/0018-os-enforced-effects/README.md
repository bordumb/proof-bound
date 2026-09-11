# Experiment 0018: OS-enforced effects and sound invalidation

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-011
- **Status:** concluded; revise
- **Registered:** 2026-09-03
- **Started / concluded:** 2026-09-03 / 2026-09-03
- **Subject:** Proofbound `fec933af98eeb8336f095fcffe3282e8f74baa7d`
- **Operator:** Codex (GPT-5)

## Why this experiment

EXP-LANG-003 showed that a declared dependency set is not necessarily the set
that a subprocess consumes. A checker read an undeclared file, so declared-only
identity retained stale evidence. Adding a repository revision prevented that
reuse only by invalidating unrelated work and could not explain the changed
dependency.

EXP-LANG-005 repaired that falsifier inside a research interpreter that
mediated every operation. It did not establish that an ordinary Python, Node,
or Rust process is similarly closed. Command provenance identifies what was
launched; it does not prove which files, environment values, executables, or
network endpoints the child could access.

This experiment tests the missing boundary. A runner composes a cleared,
allowlisted environment with a separately identified operating-system policy.
The policy denies project-file reads outside an exact input set, reviewed-root
writes, writes outside one ephemeral tree, network access, and child executable
launches outside an exact set. Runtime and system-library reads required merely
to start the registered interpreter or executable remain a separately named
toolchain boundary; they are not misreported as project dependencies.

The first implementation target is the available macOS Seatbelt
`sandbox-exec` mechanism. This is a platform-bounded research instrument, not
a claim that Seatbelt is a stable public API, that the kernel is verified, or
that the same policy exists on Linux or Windows. Unsupported or behaviorally
incompatible hosts must report the experiment unanswered rather than falling
back to an unenforced process.

## Questions (pre-registered)

1. **Q1 — Enforced authority.** Can the registered boundary prevent successful
   assurance execution after an undeclared project read, unregistered
   executable launch, undeclared environment access, network attempt,
   reviewed-root write, or ephemeral-write escape? **Pass:** all three language
   subjects complete their positive route, every registered authority attack
   is denied with its exact outcome class, and no denied run yields reusable
   evidence. **Falsifier:** an attacked process observes the protected value,
   changes a protected path, contacts the listener, launches the forbidden
   executable, or is classified reusable.
2. **Q2 — Sound and narrow invalidation.** Does the enforced input model repair
   the undeclared-read falsifier without a global repository revision?
   **Pass:** changing any consumed registered file, relevant permission,
   registered absence, environment value, executable, or policy identity
   changes the execution identity; changing the frozen unrelated control does
   not; and attempts to consume that control without registration are denied.
   **Falsifier:** one load-bearing change retains an identity, one unrelated
   change invalidates a subject, or an undeclared read succeeds.
3. **Q3 — Independent interpretation.** Can an independent implementation
   validate the enforcement receipt and derive the same invalidation decision?
   **Pass:** Rust and separately implemented Python validators emit
   byte-identical canonical reports for every positive execution and reject
   every receipt, identity, ordering, alias, and downgrade attack with its
   registered code. **Falsifier:** either validator accepts an attack, their
   canonical bytes differ, or validation requires executing the subject
   language or trusting an authored `sandboxed` Boolean.
4. **Q4 — Cross-language boundary.** Is one backend-neutral effect contract
   sufficient for representative Python, TypeScript/Node, and Rust processes?
   **Pass:** the same effect and receipt types execute all three subjects, with
   language-specific runtime roots retained only as typed toolchain inputs and
   no language-name branch in common validation or invalidation. **Falsifier:**
   a language requires unrestricted project, environment, network, process, or
   write authority, or common semantics branch on its language name.
5. **Q5 — Honest feasibility and trust.** Can the prototype stay small,
   deterministic, and explicit about its platform and trusted computing base?
   **Pass:** ten repetitions retain identical semantic reports; reviewed source
   remains byte-identical; all registered time, size, and source ceilings hold;
   and the result names the exact OS, policy, enforcement executable, runtime,
   and unavoidable system-read roots. **Falsifier:** the runner silently falls
   back, mutates reviewed source, omits a trusted boundary, exceeds a ceiling,
   or presents a single-platform result as portable enforcement.

## Candidate contract

```text
EnforcedExecutionPlan {
  schema: "proofbound-research-enforced-plan/1"
  subject: SubjectIdentity
  platform: PlatformIdentity
  enforcement: EnforcementIdentity
  runtime: ArtifactIdentity
  project_reads: Set<FilePreimage | AbsencePreimage>
  toolchain_read_roots: Set<PathBoundary>
  environment: Set<ValueIdentity>
  executable_allowlist: Set<ArtifactIdentity>
  ephemeral_write_root: PathBoundary
  network: Denied
  reviewed_writes: Denied
}

EnforcementReceipt {
  schema: "proofbound-research-enforcement-receipt/1"
  plan_identity: Sha256
  policy_identity: Sha256
  command: TypedArgv
  run: RawExitAndOutputIdentity
  preimages: Set<ArtifactIdentity | AbsenceIdentity>
  postimages: Set<ArtifactIdentity>
  enforcement_result: Enforced | Denied | Unsupported
  reusable: Bool  // derived by the validators, never accepted from the child
}
```

The runner derives policy bytes from the typed plan and binds those exact
bytes. It clears the parent environment before adding registered values. A
successful child emits only application output; it cannot author the plan,
receipt, enforcement classification, cache identity, or assurance status.

The runner snapshots registered project preimages and the reviewed tree before
execution, verifies them again afterward, and admits writes only below a fresh
ephemeral root. Required runtime and system-library reads are represented as a
toolchain boundary rather than hidden inside the project closure. A policy
that permits the whole repository, home directory, or parent workspace fails
the experiment even if every positive command exits zero.

## Registered subjects

- one Python 3.12 programme that reads an exact input and writes one exact
  ephemeral output;
- one Node 22 programme with the same semantic operation;
- one precompiled Rust programme with the same semantic operation;
- one unrelated project file used as the invalidation negative control;
- one registered absence preimage; and
- a local network listener and forbidden child executable used only by attacks.

The corpus commit will freeze standalone sources and expected semantic output.
It will not reuse broad package-manager or compiler operations whose ambient
startup requirements would obscure the boundary under test.

## Registered measurements

- `M-EFX-001`: positive subjects completed / 3;
- `M-EFX-002`: exact authority attacks denied / registered attacks;
- `M-EFX-003`: denied runs classified reusable, target zero;
- `M-EFX-004`: load-bearing changes that retain execution identity, target zero;
- `M-EFX-005`: unrelated changes that alter execution identity, target zero;
- `M-EFX-006`: Rust/Python canonical report disagreements, target zero;
- `M-EFX-007`: reviewed-root byte or mode changes, target zero;
- `M-EFX-008`: repeated semantic-report identities / 10;
- `M-EFX-009`: policy, receipt, report, and implementation sizes; and
- `M-EFX-010`: execution time and sandbox overhead, descriptive only.

## Scope

- **In:** macOS Seatbelt enforcement; exact project reads and absence
  preimages; file permissions; cleared environment; exact executable
  allowlists; denied network; denied reviewed writes; bounded ephemeral writes;
  Python, Node, and Rust subjects; exact invalidation; Rust/Python independent
  receipt validation; adversarial policy and receipt mutation.
- **Out:** verified-kernel claims; Linux and Windows parity; production cache
  adoption; arbitrary package-manager/build-system closure; syscall-complete
  tracing; distributed execution; containers; performance competitiveness;
  secrets; clock and randomness virtualization; human usability.

## Procedure

1. Commit this preregistration before adding fixtures, policy generation, or
   experiment-specific implementation.
2. In a separate commit, freeze exact sources, expected output, platform probe,
   policy rules, attacks, invalidation scenarios, and ceilings.
3. Implement the runner and first validator in Rust without opening the frozen
   expected-result file during derivation.
4. Implement receipt validation and report derivation independently in Python.
5. Execute positive subjects and attacks for ten repetitions on the registered
   host. A missing or incompatible enforcement mechanism yields an unanswered
   platform result, never an unenforced fallback.
6. Retain the raw canonical result before interpretation.
7. Conclude Q1--Q5 separately and update the programme. Bounded success may
   justify a production-oriented follow-up; it does not itself modify cache
   policy or claim general operating-system portability.

## Decision rule

- **Pass:** Q1--Q5 pass over the complete frozen macOS corpus.
- **Revise:** enforcement is sound for a strict subset, and every unsupported
  effect or runtime is retained as an explicit non-reusable boundary.
- **Stop:** an undeclared dependency can influence reusable evidence, the
  runner falls back without enforcement, cross-language support requires
  unrestricted authority, or independent validation cannot distinguish an
  enforced run from an authored success claim.
