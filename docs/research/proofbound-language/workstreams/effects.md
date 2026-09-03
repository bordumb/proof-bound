# WS-FX: effects and capabilities

- **Status:** next; EXP-LANG-005 preregistration required
- **Hypothesis:** H5
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

## Exit criteria

At least two demonstrated defects fail before expensive execution, observed
effects cannot exceed declared effects, and OS-enforced versus language-level
guarantees remain explicit.
