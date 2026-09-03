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

## 2026-09-03 — Independent Python checker implemented

Implemented the second checker from the frozen records. It independently
decodes the closed AST, validates types and source joins, evaluates every
explicit row, derives contract reachability and mutant counterexamples, and
recomputes identities. The complete ten-repetition Rust and Python model
reports are byte-identical at
`sha256:c0eeb773bcb8e32ccd183edfcd7e05935e07ca3a5800610417003db0f79646ce`.
Neither engine opened `expected.json` while deriving that report.

## 2026-09-03 — Expected-value evaluator implemented

Added the evaluator after both model reports existed. It runs both engines
before opening the frozen expected values, checks exact structural and vacuity
attacks, correct-obligation coverage, mutant counterexamples, deterministic
identity, independent byte agreement, and every preregistered complexity
ceiling. No retained execution artifact existed when this entry was added.

## 2026-09-03 — Experiment executed

Executed both checkers ten times and then opened the frozen expected values.
The correct relation satisfied 34/34 reachable obligations. All six mutants
were killed with complete first counterexamples, all 20 attacks rejected with
their exact codes in both engines, and the complete model report bytes matched.
The suite contains 24 AST nodes over 14 carrier values and ten variables; the
5,307-byte model report remains below every registered ceiling. The retained
execution is
`sha256:9986bfb87196b96899cda5bfb61406f8d710af99929abea99884abfb2af4ff5b`.
