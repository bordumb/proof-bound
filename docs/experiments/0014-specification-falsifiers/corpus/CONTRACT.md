# Frozen specification-adequacy contract

This corpus evaluates a finite typed specification against explicit execution
tables. It neither executes a parser nor proves a proposition over unbounded
bytes.

## Registered universe

`universe.json` is authority separate from the candidate suite. It defines two
finite carriers: four values and ten input-byte cases representing four valid
encodings plus empty, truncated, wrong-length, out-of-range, trailing, and
noncanonical forms. Every contract must name the complete lexical case set for
its carrier. It also freezes ten typed variables, five required property roles,
and six required mutant identities.

`contracts.json` binds the universe by raw SHA-256 and contains exactly one
contract per required role. Expressions are closed records with constructors
`bool`, `int`, `var`, `not`, `and`, `eq`, `le`, `add`, and `implies`. Arithmetic
is nonnegative checked integer arithmetic. `requires` and `ensures` must type as
Boolean. Every result obligation must reference a result-role variable.
Literal-true ensures and an implication with an unsatisfiable premise are
vacuous even if their truth tables pass.

Every contract must have a reachable precondition. For each required case
where `requires` holds, the correct table must satisfy `ensures`. The complete
contract list and required-mutant list are strict lexical sets and must equal
the external universe registration.

## Explicit execution tables

`execution-tables.json` contains one lexical table per correct or mutant
implementation. Each table contains exactly every case in both carriers. Row
positions are fixed by `row_fields`: case ID, result success, decoded integer,
round-trip equality, canonical equality, consumed bytes, and evaluation steps.
An engine may not simulate, repair, or infer a missing row.

The correct table must satisfy all five contracts. Every required mutant must
fail at least one contract, and its report must retain the first lexical
contract/case counterexample plus the complete failing-contract set. A mutant
that satisfies the entire suite yields `SPEC-MUTANT-SURVIVED`.

## Identities and reports

The suite identity uses domain `proofbound-research-specification-suite/1` over
canonical JSON. The adequacy report uses domain
`proofbound-research-specification-report/1` over canonical JSON excluding only
its `identity`. Reports retain contract reachability and obligation counts,
correct-table results, mutant counterexamples, AST node count, carrier count,
and source identities. Derived lists are lexical strict sets.

The evaluator opens `expected.json` only after both independent reports exist.
All thresholds are integer ceilings. Expected values are test oracles, never
inputs used to fill a candidate report.
