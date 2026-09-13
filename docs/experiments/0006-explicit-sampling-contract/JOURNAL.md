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

## 2026-09-02 — Adapter-owned driver passed

Implemented the candidate driver ABI at `f4e5ec8a717e218c876547d508a399e517365abf`.
Application modules export only a generator and predicate. The driver owns the
seed, successful-case budget, persistence and shrink policies, framework
execution, counters, and exclusive-create report. Hypothesis and fast-check
both completed 100 registered cases and emitted the same closed observation
shape. Deliberately false properties emitted typed counterexamples before
both drivers exited 1.

The common counter semantics are now exact: attempted cases are predicate
invocations; completed cases returned successfully; skipped cases are
predicate precondition rejections. Values discarded internally by a generator
before predicate invocation are not attempts. A passing observation must
complete the exact registered budget. A counterexample must occur before that
budget completes.

Independent Rust and Python validators reconstruct generator and contract
identities from separate registration plus live closure bytes. Both reject all
ten preregistered attacks with their registered class and contain no branch on
`hypothesis` or `fast-check`. Q1, Q2, and Q4 pass at this research boundary;
Q3 selects the adapter-owned driver. Existing production receipts remain
legacy until a new wire adopts this contract, so the result does not silently
upgrade the completion captures.
