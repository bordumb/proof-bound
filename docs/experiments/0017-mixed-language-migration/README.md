# Experiment 0017: Mixed-language native migration

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-008
- **Status:** preregistered; not executed
- **Registered:** 2026-09-03
- **Started / concluded:** — / —
- **Subject:** Proofbound `8e210c8da2d40ed5231e407d3e90d159ddddefdc`
- **Operator:** Codex (GPT-5)

## Why this experiment

EXP-LANG-007 established one bounded native research component. It did not
show that Python or TypeScript can call that component without converting its
source proof into an application proof, hiding bridge/runtime assumptions, or
creating a backend-specific common kernel. Those are the adoption boundary's
central risks.

This experiment freezes one packet contract, two foreign callers, a legacy and
native-backed phase, and one mixed claim graph. Python and TypeScript execute
the same encode/decode cases first through a direct legacy implementation and
then through the exact EXP-LANG-007 artifact. Independent Rust and Python
kernels validate the observations and derive the mixed graph. The native
component may retain its finite source assurance; foreign application claims
must remain tested and assumption-bearing.

## Questions (pre-registered)

1. **Q1 — Exact foreign contract.** Can one backend-neutral ABI bind operation,
   input/output bytes, result/error encoding, exact consumption, artifact,
   runtime, callback policy, and exception policy for both callers? **Pass:**
   Python and TypeScript agree on every legacy and native-backed call; both
   independent kernels accept the same canonical observations; all ABI,
   serialization, version, callback, exception, runtime, and observation
   attacks reject exactly. **Falsifier:** caller meaning depends on an unstated
   language convention or same-cardinality substitution survives.
2. **Q2 — Honest coexistence.** Can native and foreign evidence coexist in one
   graph without assurance coercion? **Pass:** the native parser claim remains
   universal only over its declared four-value type and assumption-bound at the
   artifact; both application claims remain tested; the graph retains every
   foreign runtime and bridge assumption; all family and status upgrades
   reject. **Falsifier:** native proof proves an application, foreign tests
   prove the parser, or any required assumption disappears.
3. **Q3 — Selective migration.** Does replacing the legacy parser dependency
   strengthen only the registered packet-dependent claims while preserving
   public meaning? **Pass:** exactly the native component and two packet caller
   claims change derivation; one unrelated display claim is byte-identical;
   all public claim contracts remain identical; all dependency, claim,
   unaffected-node, and migration-set attacks reject. **Falsifier:** migration
   changes public meaning, upgrades a foreign claim, or rewrites an unrelated
   node.
4. **Q4 — Independent adversarial agreement.** Do two kernels agree on the
   complete mixed graph and every registered attack? **Pass:** Rust and Python
   produce byte-identical baseline and migrated reports in ten repetitions and
   reject all 30 attacks with exact codes. **Falsifier:** any unexplained
   disagreement, unstable identity, accepted attack, or hidden backend branch
   remains.
5. **Q5 — Bridge feasibility.** Is the bounded bridge understandable and small
   enough to inform a language decision? **Pass:** each caller is at most 300
   nonblank non-comment lines, each common kernel 1,400 lines, the canonical
   report 64 KiB, execution 30 seconds, and the final explanation names the
   native fact, two foreign evidence ceilings, all remaining assumptions, and
   exact affected claims without raw tool noise. **Falsifier:** a caller needs
   ambient callbacks/exceptions, the common model names a language/tool, a
   limit fails, or the report obscures what became stronger.

Passing is evidence only for the frozen packet contract, two runtimes, exact
artifact, and finite cases. It cannot establish safe arbitrary FFI, memory,
concurrency, callback, exception, or deployment behavior.

## Candidate migration

```text
baseline                              migrated
--------                              --------
Python app ── tested legacy parser    Python app ── tested bridge ─┐
TypeScript app ─ tested legacy parser TypeScript app ─ tested bridge├─ exact PBVM artifact
unrelated display claim               unrelated display claim ─────┘  source assurance
                                                                      stays separate
```

The common graph names `native-component`, `foreign-component`, `contract`,
`artifact`, `runtime`, `observation`, `assumption`, `claim`, `derivation`, and
`migration`. It may not name Python, TypeScript, Node, pytest, Vitest, npm, or
another backend. Language and runtime identities are typed data at the foreign
boundary.

## Registered measurements

- `M-FB-001`: exact foreign calls accepted / frozen call count;
- `M-FB-002`: Python/TypeScript call disagreements;
- `M-FB-003`: Rust/Python graph and attack disagreements;
- `M-FB-004`: accepted assurance coercions or omitted assumptions;
- `M-FB-005`: derived affected claims versus frozen migration set;
- `M-FB-006`: stable report identities / ten repetitions;
- `M-FB-007`: exact attack rejections / 30; and
- `M-FB-008`: caller/kernel lines, report bytes, and elapsed time.

## Scope

- **In:** EXP-LANG-007 bytecode; one versioned packet ABI; pure encode/decode;
  Python and TypeScript callers; legacy and migrated phases; deterministic
  canonical JSON; exact runtime/artifact identities; explicit no-callback and
  error-as-data policies; mixed claim graph; independent Rust/Python kernels;
  30 attacks.
- **Out:** production adapters; shared memory; native machine code; dynamic
  linking; host callbacks; exceptions across the boundary; asynchronous or
  concurrent calls; ownership/lifetime transfer; networking; deployment;
  performance claims; arbitrary foreign code; human usability study.

## Procedure

1. Commit this preregistration before contract, cases, callers, graph, attacks,
   expected values, or implementation.
2. Freeze the ABI, call cases, legacy/migrated graph, runtimes, artifact,
   assumptions, attack corpus, expected counts, and complexity ceilings.
3. Implement and execute Python and TypeScript callers independently.
4. Implement the Rust mixed-graph kernel, then an independent Python kernel.
5. Add the evaluator only after both kernels agree. Execute both phases and all
   attacks ten times before opening expected values; retain the result.
6. Decide Q1--Q5 separately. Do not call a tested foreign application proved.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0017-F001 | Reserved for execution. | — | pending |

## Outcome

Q1--Q5 are unanswered. No contract, corpus, caller, or implementation exists.
