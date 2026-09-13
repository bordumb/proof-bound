# Experiment 0007 journal

[Experiment registration](README.md)

Append-only execution notes begin after the preregistration commit. Corrections
are new entries rather than edits to earlier observations.

## 2026-09-02 — Public typed API falsified the unchanged contract

Built the isolated proptest `1.11.0` probe at `a30e63d`. The registered
ChaCha/fixed-seed run passed 100 cases. A deliberately false property returned
a typed minimal counterexample, but its 23 predicate invocations could not be
partitioned authoritatively into the initial failure, accepted shrinks,
rejected shrink candidates, or framework replays. Proptest keeps success and
rejection counters private and exposes no accepted-shrink counter through the
stable typed API. Parsing `Display` output or reading private state was rejected
by the preregistration.

Executed the registered RNG substitution with the same proptest version and
seed. XorShift produced 25 counterexample predicate invocations while ChaCha
produced 23. Both executions would have the same EXP-0006 contract because it
does not represent RNG algorithm. This triggers Q1's registered falsifier.
The unavailable counters independently trigger Q2 and Q3.

The holdout therefore rejects one exact cross-framework execution contract.
It does not reject a shared sampled-property semantic family. The next design
must separate common sampling intent, typed backend execution controls, and an
explicit observation capability rather than inventing unavailable counts.
The remaining attacks were not executed after the decisive stop conditions.
