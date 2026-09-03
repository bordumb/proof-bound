# Experiment 0009 journal

[Experiment registration](README.md)

Append-only execution notes begin after the preregistration commit. Corrections
are new entries rather than edits to earlier observations.

## 2026-09-03 — Generated differential passed

Execution began only after the preregistration and subject-binding commits.
The research prototype at `5fbf05b` implemented the registered fact,
judgment, rule, and trace schemas in Rust, plus a deterministic generator over
the six registered evidence routes. A separately written Python checker uses
its own decoder and rule table rather than importing the Rust implementation.

Both implementations accepted 500 valid programs with identical conclusions
and trace identities. They also agreed on all 500 single-mutation adversarial
programs, covering each of A001–A016 between 31 and 32 times. The run exercised
all eleven closed rules and introduced no backend-named common rule.

The consequence test behaved differently by design: making a consumed
evidence fact unavailable blocked `evidence-valid`, while removing unused
duration telemetry preserved the same admitted conclusion and emitted no
alert. Q1–Q5 therefore pass for the registered finite domain. The result
supports explicit derivation traces in the next Assurance IR revision; it does
not establish completeness for every production route or authorize a wire
migration.
