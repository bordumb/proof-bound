# Experiment 0006 journal

[Experiment registration](README.md)

Append-only execution notes begin after the preregistration commit. Corrections
are new entries rather than edits to earlier observations.

## 2026-09-02 — Registration and subject identities frozen

The preregistration landed at
`c5c4e256f97606ddfa5b8044f3b5152f8919adfd` before either candidate route
executed. Exact registration and subject identities are recorded in the
artifact ledger. The ordinary-runner experiment must leave both application
test files byte-identical; any instrumented copy lives outside those paths and
is identified separately.

## 2026-09-02 — Ordinary-runner route failed

Executed both frozen properties without changing their application source.
Hypothesis passed 100 examples and printed zero failures/invalid examples plus
the `max_examples=100` stop reason, but only as human terminal statistics. Its
observed output omitted the actual seed, framework identity, generator
identity, and shrink count. The seed was present only in command provenance.

Vitest emitted strict JSON and passed the exact selected test node, but its
report contained no nested fast-check seed, run count, generator, skip, shrink,
or effective configuration fields. A test-node success Boolean is therefore
not an observation of the sampling contract.

The ordinary-runner route fails Q1 and Q2. Parsing Hypothesis prose or treating
Vitest pass/fail as fast-check metadata would violate the preregistered
authority rule. The driver-ABI route remains unexecuted.

## 2026-09-02 — fast-check setup instrumentation failed closed

Tried to attach fast-check's public reporter from adapter-owned Vitest setup
without changing the application property. Global configuration and a module
mock did not intercept the fast-check instance used by the test under Vitest's
module isolation. Directly replacing the imported `assert` export failed
because the ESM namespace is read-only.

The final prototype adds an adapter-owned global teardown that requires and
strictly decodes the structured report. The property and outer Vitest node
passed, no sampling report appeared, and teardown forced process exit 1 with
`sampling observer did not emit strict JSON`. This is the correct safety
outcome but fails Q2. TypeScript therefore joins Python in requiring a driver
that is structurally in the property execution path; setup instrumentation is
not sufficient.
