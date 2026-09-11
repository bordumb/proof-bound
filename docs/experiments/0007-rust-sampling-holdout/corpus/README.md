# EXP-0007 bounded corpus

`rust/` is an isolated, research-only Cargo workspace pinned by its own lock.
It imports the frozen allowance kernel, proptest `1.11.0`, and the shared
canonical JSON implementation. It is not a production Proofbound adapter.

The property module exports a bounded request strategy plus one real and one
deliberately false predicate. The probe uses proptest's public `Config`,
`TestRunner`, and typed `TestError` APIs. It records only facts available
without private-field access or human-output parsing. Cargo targets and
proptest regression files are generated state and must not be committed.
