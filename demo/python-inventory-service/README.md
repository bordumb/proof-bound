# Proofbound Python inventory service

This pure-Python reference vertical shows that Proofbound is an assurance
framework, not a Rust-only test wrapper. It registers exact pytest examples, a
registered full-file mutation caught by one exact witness, a seeded Hypothesis
property, a zero-diagnostic mypy inventory, an independent checker, and a wheel
reproduced twice from sealed source.

The board is intentionally honest. These routes establish empirical support,
not a theorem about every Python execution. Dynamic dispatch, monkeypatching,
import-order effects, interpreter correctness, analyzer soundness, and the
external accuracy of supplied inventory capacity remain outside the claim.

## Claims and trust

`PY-RESERVATION-001` says accepted reservations never exceed the supplied
capacity. `PY-WHEEL-001` says the exact registered wheel bytes reproduce. Both
depend on `PY-RUNTIME-001`, which makes the runtime and external-capacity trust
boundary explicit.

Install the exact development environment from `requirements-dev.txt`, then
run `proofbound doctor`, `proofbound check`, `proofbound status`, and
`proofbound release`. Verify the emitted release with the standalone
`proofbound-verify` binary.
