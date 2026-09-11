# Experiment 0014: Specification falsifiers

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-009
- **Status:** concluded; Q1--Q5 passed over the frozen finite corpus
- **Registered:** 2026-09-03
- **Started / concluded:** 2026-09-03 / 2026-09-03
- **Subject:** Proofbound `5865b76bce7aed6ed89eeab0ec8c6b7c74a93f27`
- **Operator:** Codex (GPT-5)

## Why this experiment

A language can make an assurance statement look formal without making it
meaningful. An implication with an unreachable precondition passes vacuously.
An empty carrier makes every universal statement true. A postcondition that
does not constrain the result accepts an always-success implementation. Two
requirements can be individually plausible but jointly inconsistent. A
contract can also omit precisely the input class where a defect lives.

These failures are dangerous prerequisites for a native Proofbound parser:
independent proof checking is not useful if the proposition being checked is
empty, contradictory, or too weak to distinguish the implementation from
registered semantic mutants. This experiment therefore tests a bounded
specification-adequacy kernel before the native executable prototype exists.
It does not claim to decide whether arbitrary mathematical specifications are
useful.

## Questions (pre-registered)

1. **Q1 — Closed typed contracts.** Can a small typed contract AST reject
   ambiguous or ill-typed specifications before evaluation? **Pass:** Rust and
   Python reject every registered unknown constructor, duplicate identity,
   incomplete or duplicate carrier, unknown variable, type mismatch, forged
   identity, and noncanonical-order attack with its exact registered code.
   **Falsifier:** either implementation accepts an ambiguous record or the two
   implementations disagree on its meaning.
2. **Q2 — Non-vacuity and consistency.** Can the candidate expose bounded
   empty-domain, unreachable-precondition, tautological, result-independent,
   inconsistent, and vacuous-implication contracts? **Pass:** every registered
   defect produces its exact code and a deterministic finite witness or
   counterexample where one exists; the accepted suite has a nonempty complete
   carrier, reachable preconditions, result-constraining obligations, and at
   least one satisfying result per required input. **Falsifier:** a defective
   contract is admitted, a valid one is rejected, or a diagnostic relies on
   prose rather than the typed expression and carrier.
3. **Q3 — Semantic mutant adequacy.** Does the suite distinguish the intended
   bounded parser relation from registered alternatives? **Pass:** the correct
   relation satisfies every obligation and each frozen always-success,
   always-error, noncanonical-acceptance, ignored-length, payload-substitution,
   and trailing-byte mutant is rejected by at least one named obligation in
   ten repetitions. **Falsifier:** any mutant satisfies the full suite, the
   correct relation fails it, or a mutant result is inferred rather than
   present in the frozen execution table.
4. **Q4 — Independent deterministic checking.** Can independent engines emit
   the same complete adequacy report? **Pass:** Rust and Python reports are
   byte-identical, all attacks reject exactly, witnesses name exact contract,
   carrier value, implementation, and evaluated expression, and ten runs are
   stable. **Falsifier:** ordering changes bytes, an identity can be forged, a
   witness is incomplete, or either engine consumes the expected-result file
   while deriving its report.
5. **Q5 — Native-parser prerequisite.** Is the bounded specification form
   adequate to preregister the first native parser without backend-named
   predicates? **Pass:** one suite expresses total encode/decode round trip,
   rejection of malformed encodings, canonical re-encoding, exact consumption,
   and bounded termination using only typed values and relations; the suite
   remains within frozen node, carrier, and report-size ceilings. **Falsifier:**
   a required property needs an opaque callback or tool name, or the candidate
   exceeds a frozen ceiling.

## Candidate model

```text
SpecificationSuite {
  carriers: Map<CarrierId, Ordered<FiniteValue>>
  implementations: Ordered<ExecutionTable>
  contracts: Ordered<Contract>
  required_mutants: Set<ImplementationId>
}

Contract {
  id, carrier, variables: TypedEnvironment,
  requires: BoolExpr,
  ensures: BoolExpr,
  role: Safety | RoundTrip | Canonicality | Consumption | Termination
}

AdequacyReport {
  correct_accepted,
  contract_coverage,
  mutant_rejections,
  non_vacuity_witnesses,
  identity
}
```

Expressions use a closed, backend-neutral Boolean/equality/comparison language
over finite bytes, bounded integers, result tags, and exact consumption. The
corpus supplies explicit execution tables. The checker never runs or trusts a
parser implementation while deciding specification adequacy.

## Registered measurements

- `M-SP-001`: exact structural/type attack rejections / registered attacks;
- `M-SP-002`: contracts with at least one reachable precondition / contracts;
- `M-SP-003`: required inputs with at least one satisfying allowed result /
  required inputs;
- `M-SP-004`: result-constraining contracts / contracts registered as result
  obligations;
- `M-SP-005`: registered mutants killed / registered mutants;
- `M-SP-006`: correct implementation obligations satisfied / obligations;
- `M-SP-007`: Rust/Python canonical report disagreements;
- `M-SP-008`: stable report identities / ten repetitions; and
- `M-SP-009`: maximum AST nodes, carrier values, and canonical report bytes.

## Registered attacks

The machine preregistration fixes 20 exact attacks and codes covering unknown
constructors, duplicate contracts and carrier values, empty and incomplete
carriers, unknown variables, type errors, unsatisfiable requirements,
tautological and result-independent postconditions, inconsistent results,
vacuous implications, empty obligation sets, unknown and omitted mutants,
three surviving semantic mutants, forged identities, and noncanonical order.

## Scope

- **In:** one finite length-prefixed byte-format relation; a closed typed
  expression AST; explicit finite carriers and execution tables; six semantic
  mutants; five parser-property roles; Rust/Python independent checkers; exact
  witnesses and ten repetitions.
- **Out:** proving arbitrary contracts non-vacuous; SMT solver validation;
  unbounded integers or byte strings; deciding whether prose requirements are
  complete; human specification usability; running the future native parser;
  production schema adoption.

## Procedure

1. Commit this preregistration before contracts, carriers, execution tables,
   expected values, or implementation.
2. Freeze the intended finite relation, correct and mutant tables, typed
   contracts, attacks, complexity ceilings, and metric algorithms separately.
3. Implement the validator and evaluator in Rust.
4. Implement the checker independently in Python.
5. Execute both ten times before opening expected outcomes; retain canonical
   reports and exact counterexamples.
6. Conclude Q1--Q5 separately. Treat a finite exhaustive result as bounded,
   never as an unbounded theorem about future native code.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0014-F001 | Independent typed checkers emitted the same complete adequacy report bytes. | Model report `sha256:c0eeb773bcb8e32ccd183edfcd7e05935e07ca3a5800610417003db0f79646ce`; ten stable repetitions | retain the finite contract AST and report shape as native-parser inputs |
| EXP-0014-F002 | Reachability and result dependence expose registered forms of vacuity before a specification is accepted. | Five reachable contracts; exact rejection of empty/incomplete carriers, unreachable preconditions, literal tautology, result-independent postcondition, contradiction, and false-premise implication | require specification-adequacy validation before accepting a proof result |
| EXP-0014-F003 | The candidate suite distinguishes the intended relation from every registered semantic alternative. | Correct relation 34/34 obligations; six of six explicit mutants killed with complete first counterexamples | admit the suite as a bounded prerequisite for EXP-LANG-007 |
| EXP-0014-F004 | Structural validity alone is insufficient: plausible result-constraining weakenings can still admit bad implementations. | Three weakened suites passed structural checks but were rejected because always-success, always-error, or noncanonical-acceptance survived | retain mutation adequacy as a separate typed result, not a parser/type-check proxy |
| EXP-0014-F005 | The experiment remains finite and table-bound. | 14 carrier cases, 24 AST nodes, explicit execution tables, no native parser or proof search | do not call the result an unbounded proof or general specification-completeness theorem |

## Outcome

All five questions pass over the frozen finite model:

- **Q1 passed:** both engines rejected every structural, type, identity, and
  ordering attack exactly.
- **Q2 passed:** all five accepted contracts have reachable preconditions and
  satisfying correct results. Every registered empty, vacuous,
  result-independent, or inconsistent form rejected with its exact code.
- **Q3 passed:** the correct relation satisfied 34/34 obligations and each of
  six explicit mutants failed at least one named contract/case.
- **Q4 passed:** the ten-repetition independent reports were byte-identical,
  carried complete counterexamples, and all 20 attacks agreed exactly.
- **Q5 passed:** round trip, malformed rejection, canonicality, exact
  consumption, and bounded termination fit the backend-neutral AST using 24
  nodes over 14 cases; the 5,307-byte model report stayed below the frozen
  ceilings.

This result authorizes use of the five-contract suite as a bounded input to the
native-parser experiment. It does not prove a future parser, establish
completeness for unbounded byte strings, or show that automated adequacy can
replace specification review.
