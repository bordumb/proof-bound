# EXP-0006 bounded corpus

The corpus contains backend-specific generator/predicate exports and canonical
backend-neutral contracts and observations. The Python and TypeScript modules
contain no assurance status, admission decision, seed, or case budget. Those
facts are owned by the adapter driver.

`contracts/` is ordinary registered JSON and therefore ends with a newline.
`observations/` is a readable checked-in copy of each positive driver report;
the drivers themselves emit compact canonical JSON without a trailing newline.
Tests remove only the fixture newline before applying the strict observation
decoder. Execution results record the digest of the exact emitted bytes.

The deliberately false modules verify that both drivers emit a typed
counterexample before returning a nonzero process status. They are not
positive assurance evidence.
