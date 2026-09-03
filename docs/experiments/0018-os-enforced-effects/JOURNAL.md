# Experiment 0018 journal

[Experiment registration](README.md) · [Artifact ledger](ARTIFACTS.md)

This journal is append-only after the preregistration commit.

## 2026-09-03 — Preregistered

Registered the OS-enforced effects study after the dependency-ordered
EXP-LANG-001 and EXP-LANG-003--010 programme concluded. EXP-LANG-003 supplies
the undeclared-read falsifier; EXP-LANG-005 supplies the bounded mediated
candidate. No experiment-specific subject, policy generator, runner, receipt
validator, attack executor, or result existed when this entry was added.

The registration deliberately targets one available macOS mechanism. Missing
or incompatible enforcement makes the platform question unanswered and may
not activate an ordinary subprocess fallback. Runtime and system-library reads
remain a named toolchain boundary rather than being hidden or described as
exact project dependencies.

## 2026-09-03 — Corpus frozen

After the preregistration commit, froze three standalone implementations of one
operation, four regular project preimages, one intentional absence, the
backend-neutral contract, expected output, exact counts, and complexity
ceilings. The Python, Node, and Rust subjects each contain the same positive,
undeclared-read, undeclared-environment, unregistered-executable, network, and
write attack modes. Their presence does not count as execution.

The corpus inventory is
`sha256:9686074a5cd8e5f2b3f0018ab95104f697bce292e0e948482220ec378780bd43`.
The positive output is 32 bytes with SHA-256
`6897a0406cd3b5b1aa1c9fb86c784f443606a03f487d2cc00e9fd1a0e2144d22`.
No experiment-specific runner, policy generator, receipt validator, attack
executor, or result existed when these controls were frozen.
