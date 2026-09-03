# Experiment 0014 journal

[Experiment registration](README.md)

Append-only execution notes begin after the preregistration commit.

## 2026-09-03 — Preregistered

Registered the specification-falsifier study before creating its carrier,
contracts, execution tables, attacks, expected values, or implementation. The
study is deliberately finite and table-driven so it can measure whether a
typed specification distinguishes the intended relation from named mutants
without claiming general theorem proving or native-parser correctness.

## 2026-09-03 — Corpus frozen

Committed two carriers with 14 total cases, ten typed variables, five required
property roles, the five-contract candidate, one correct and six explicit
mutant execution tables, all 20 preregistered attacks, and complexity ceilings.
The contract suite binds the separately hashed universe. No checker existed
when the corpus was frozen, and the expected file contains no filled checker
output.

## 2026-09-03 — Rust checker implemented

Implemented the first checker after the corpus commit. It validates the closed
typed expression AST, external universe binding, complete finite carriers,
explicit execution-table shape, reachable requirements, result-constraining
postconditions, direct inconsistency and vacuous implication, correct-table
obligations, and exact mutant counterexamples. Its focused tests accept all 34
correct obligations, kill all six mutants, and reject all 20 frozen attacks
with exact codes. No Python checker existed when this entry was added.
