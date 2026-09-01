# ADR 0017: Replay one sealed mutation per evidence unit

Status: accepted

## Context

Experiment 0003 exposed two coupled weaknesses in mutation-witness evidence.
The version-1 registry could attach several mutations to one evidence unit, so
one failed witness removed the shared receipt from every attached claim. It
also named a callable mutant symbol but did not make Proofbound replace the
shipping implementation itself. A passing comparison test therefore showed
that two functions differed; it did not show that an ordinary registered check
would reject the shipping program after the mutation was applied.

Automatic replay adds a second wire problem. The detecting test is supposed to
exit nonzero after the mutant is installed, while version-2 evidence and release
receipts require every process in passed evidence to exit zero. Reinterpreting
that invariant in place would make old receipts mean something new.

## Decision

- Reserve `proofbound-evidence-unit/3` for Rust `mutation-witness` replay. Its
  typed `[mutation]` block points to exactly one
  `proofbound-mutation-registry/2` file.
- Make registry version 2 structurally singleton. It records one stable ID,
  subject, guard, target path and preimage digest, full-file mutant path and
  digest, exact test identity, witness-source path and digest, and nonempty
  affected-claim set.
- Require the unit ID and exact one-entry inventory to equal the mutation ID.
  Unit claims and registry `affected_claims` are the same strict lexical set.
  The registry, target, mutant, and witness are four distinct regular,
  repository-relative, symlink-free inputs with exact bytes. Every affected
  claim has the registry subject and includes the target in its semantic source
  closure. A registry or mutation ID belongs to one unit only.
- Use two independently fresh shadows. The baseline shadow retains the exact
  target preimage and the exact witness must pass. The mutant shadow starts from
  the same clean source, copies the registered full-file mutant onto the target,
  verifies the exact postimage, recompiles, recollects the same witness, and
  requires that witness alone to fail with libtest exit code 101. Compilation,
  discovery, truncation, timeout, a different exit code, or a different failing
  test fails closed. Neither shadow can modify the repository.
- Bind a mutation unit's cache key to the normalized reviewed source tree
  copied into those Cargo shadows: every regular-file path, byte digest, and
  copied permission model, under the same state-directory exclusions and
  resource limits. Shadow directories are derived only as parents of copied
  files, so empty-directory topology has no execution meaning. Package
  directories alone are insufficient because Rust can compile repository-local
  files reached through `#[path]`, `include!`, custom targets, and build scripts.
- Advance adapter observations to version 2, and canonical evidence, compiled
  state, compiled releases, and release envelopes to their coordinated
  version-3 contracts.
  The mutation detail identifies the baseline run and the one expected-failure
  run. Every other retained run still requires exit code zero. Version-2
  evidence and receipts retain their all-zero meaning and are never silently
  reinterpreted.

## Consequences

Mutation evidence now answers the operational question reviewers care about:
the exact registered check passes on the reviewed source and rejects one exact
automatically installed mutant. Claim invalidation has mutation-level rather
than batch-level granularity. Full-file replacements duplicate a small target,
but they avoid fuzzy patching, path ambiguity, context offsets, and dependence
on a separate patch tool. Larger targets should first be factored into a small
auditable decision module, as the allowance demo does.
