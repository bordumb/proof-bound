# Experiment 0008 journal

[Experiment registration](README.md)

Append-only execution notes begin after the preregistration commit. Corrections
are new entries rather than edits to earlier observations.

## 2026-09-02 — Layered model passed the three-framework corpus

Implemented the research-only model at `67e80a7`. The first fixture draft
compressed the frozen generator closures; exact reverse projection caught that
mistake before any result was written. The corrected corpus retains the full
EXP-0006 Hypothesis and fast-check intent fields and the registered EXP-0007
Rust subject, property, probe, and proptest execution controls.

Rust and independently written Python validators admitted all three positive
cases with identical intent identities, plan identities, and decisions. Both
validators then produced every preregistered A001–A012 result. In particular,
proptest's completed budget is a typed `runner-success-contract` derivation,
not an observed counter. Its attempted, skipped, and shrink facts remain
unavailable.

The notification-consequence test distinguished absence from impact. Making
the required completed fact unavailable blocked `empirical-sample-pass` and
named that fact. Removing unavailable shrink telemetry did not alter admission
or create an alert because that rule does not consume shrink telemetry. Q1–Q5
therefore pass for this bounded corpus. The result supports the layered design
for further research; it does not change a production schema or status policy.
