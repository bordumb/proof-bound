# Experiment 0016 journal

[Experiment registration](README.md)

Append-only execution notes begin after the preregistration commit.

## 2026-09-03 — Preregistered

Registered the native parser study before defining source syntax, bytecode,
verification conditions, certificates, attacks, expected outcomes, or either
implementation. The study separates solver-based proof search from independent
certificate checking and finite-type universality from bounded byte-input
exhaustiveness.

## 2026-09-03 — Native corpus frozen

Committed the thirteen-declaration source, closed grammar, exact 22-byte VM
format, five-condition solver and certificate contract, Z3 invocation, 28
attacks, six semantic mutants, complete finite carriers, and complexity
ceilings. Neither compiler nor checker existed when the corpus was frozen.

## 2026-09-03 — Rust producer implemented

Implemented the native parser, type and effect checks, deterministic 22-byte
compiler, bytecode VM, five-condition SMT producer, strictly registered Z3
runner, finite certificate producer, six-mutant evaluator, and 28-attack
executor. Ten repetitions now independently reparse, recompile, execute,
derive, and attack the candidate while reusing only the bound proof-search
receipt. Pure tests do not require Z3; the separately gated live Z3 test also
passed. The implementation is not experimental evidence until the independent
Python checker exists and the frozen procedure is executed.

## 2026-09-03 — Independent checker implemented

Implemented a Python parser, type and effect checker, bytecode compiler, VM,
certificate derivation and validator, solver-receipt validator, six-mutant
evaluator, and attack executor. The checker never invokes Z3: it reads and
hashes the registered executable, validates the retained proof-search receipt,
then independently reconstructs the complete Rust report byte for byte. It
rejects duplicate JSON keys and noncanonical report JSON before typed
validation. Cross-language tests achieved exact report-byte equality and
rejected a self-consistently rehashed scope upgrade and solver substitution.
The registered questions remain unanswered until the retained evaluator runs.

## 2026-09-03 — Expected-value evaluator implemented

Added the evaluator after both implementations achieved exact report-byte
agreement. It runs the Rust producer and Python checker before opening frozen
expected values, verifies the preregistered attack inventory, measures source,
artifact, certificate, SMT, report, implementation, and elapsed-time ceilings,
and decides Q1--Q5 independently. Its focused tests pass. No retained result
existed when this entry was added.
