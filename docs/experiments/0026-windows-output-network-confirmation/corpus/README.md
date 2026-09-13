# Experiment 0026 corpus revision

This corpus is a narrow revision of the frozen
[EXP-0018 corpus](../../0018-os-enforced-effects/corpus/README.md). All Node and
Rust source bytes, regular inputs, intentional absence, modes, arguments,
environment values, expected output bytes, repetition counts, and non-network
authority probes remain unchanged.

`python_subject.py` replaces only the EXP-0018 Python subject. Its operations
are semantically identical, but every output path uses a binary write API.
The positive output remains the exact 32 bytes
`registered-input|registered-env\n`; no platform newline translation is
accepted. The source is frozen before the EXP-0026 runner exists.

The network subject interface is unchanged: every language receives a decimal
loopback port. The new runner, not the subject, supplies a live registered
oracle for that port and binds the control and sandboxed observations.
