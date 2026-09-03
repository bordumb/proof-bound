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
