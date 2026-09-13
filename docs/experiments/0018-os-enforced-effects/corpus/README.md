# Experiment 0018 frozen corpus

This directory freezes the OS-enforced effects corpus after preregistration
and before either experiment-specific validator exists.

`contract.json` defines one backend-neutral operation, exact project
preimages, the environment allowlist, platform candidate, policy semantics,
and three subjects. `workspace/subjects/` contains independently authored
Python, Node, and Rust implementations of the same operation and authority
attacks. `expected.json` fixes counts and ceilings. The 30 attack IDs and exact
diagnostic codes are frozen by `../preregistration.json`; implementation must
not replace or silently narrow them.

The positive operation reads `registered.txt` and
`PB_REGISTERED_VALUE=registered-env`, then writes the exact text
`registered-input|registered-env\n` below a fresh runner-owned output root.
`unrelated.txt` is the invalidation negative control. `nested/outside.txt` and
`unrelated.txt` are undeclared read targets. `reviewed.txt` is the protected
write target. `must-remain-absent.txt` is intentionally absent and must stay
absent.

Interpreters and system libraries necessarily read files outside this corpus.
Those roots form an explicit toolchain boundary. The generated Seatbelt policy
must still deny the entire corpus workspace before allowing only the subject
source and registered input preimages. It must deny all writes before allowing
the fresh output tree, deny network, and deny executable launch before allowing
the exact subject runtime. A profile that broadly permits the project,
repository, workspace parent, or home directory is invalid.

The subjects deliberately contain attack branches. Their presence is not
evidence that an attack ran. The evaluator selects one mode per execution,
starts a local listener for the network case, snapshots reviewed files before
and after, and derives the receipt outside the child process.
