# WS-FX: effects and capabilities

- **Status:** EXP-LANG-011 / Experiment 0018 concluded `revise`
- **Hypotheses:** H5, H9
- **Depends on:** WS-IR authority and dependency model
- **Blocks:** Gate 2

## Objective

Represent and constrain authority such as reads, ephemeral and reviewed writes,
tool execution, environment access, network, clock, randomness, secrets, and
human judgment.

## Method

Model current mutation and packaging operations, then replay known ambient
plugin, root-write, lifecycle-script, environment, symlink, and subprocess
smuggling defects.

EXP-LANG-003 makes the first experiment narrower and testable: compare an
enforced effect boundary with declaration-only and global-revision cache
strategies against the retained undeclared-read falsifier and representative
mutation/distribution operations.

## Concluded experiment

[EXP-LANG-005 / Experiment 0012](../../../experiments/0012-effect-checked-replay/README.md)
tests a mediated effect machine, the retained hidden-read falsifier, bounded
mutation and distribution workloads, and honest opaque/external subprocess
boundaries. It does not claim that existing adapters are OS-sandboxed.

Both implementations agreed exactly across six plans, 23 attacks, and ten
repetitions. Mediation repaired the retained invalidation falsifier and the two
representative routes completed without ambient authority. Opaque processes
remained non-reusable. The synthetic external receipt tested only type and
identity binding, so real sandbox enforcement remains a separate prerequisite
for production adoption.

## Exit criteria

At least two demonstrated defects fail before expensive execution, observed
effects cannot exceed declared effects, and OS-enforced versus language-level
guarantees remain explicit.

The research exit criteria pass for the bounded interpreter. They do not
authorize claiming that current adapters enforce the same boundary.

## OS-enforced result

[EXP-LANG-011 / Experiment 0018](../../../experiments/0018-os-enforced-effects/README.md)
tested the missing external premise with a separately identified macOS
mechanism. Thirty positive runs completed, all 21 authority probes were denied,
no denied run was reusable, narrow invalidation held, and independent reports
matched across all 30 attacks. The typed boundary is supported for the frozen
corpus. The production exit remains open because the run exceeded its latency
ceiling and does not establish Linux, Windows, or syscall-complete hermeticity.
