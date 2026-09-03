# Experiment 0012 journal

[Experiment registration](README.md)

Append-only execution notes begin after the preregistration commit. Corrections
are new entries rather than edits to earlier observations.

## 2026-09-03 — Corpus frozen

Committed six typed plans, eight exact fixture files, one synthetic enforcement
receipt, all 23 preregistered attacks, and the expected plan and route-output
identities before implementing either validator. The external receipt is a
binding control only; the corpus will not claim that it represents a real OS
sandbox.

## 2026-09-03 — Rust candidate implemented

Implemented the first typed validator and mediated runner after the corpus
commit. The runner uses a fresh in-memory ephemeral output store, validates
real registered input and tool bytes, accounts for unused declarations, and
derives rather than accepts cache eligibility. Its self-tests execute every
positive plan and all 23 attacks through the same validators and include a
self-consistent trace-value substitution. No Python implementation existed
when this entry was added.

## 2026-09-03 — Independent checker implemented

Implemented the second validator and runner in Python without invoking or
importing the Rust implementation. Its focused tests pass, and its canonical
model report is byte-identical to the Rust report for the frozen corpus and ten
repetitions. This parity check is provisional until the retained experiment
executor independently revalidates both outputs and metrics.

## 2026-09-03 — Experiment executor implemented

Added an orchestrator that invokes the Rust executable and Python model
separately, requires canonical report equality, snapshots all fixture bytes and
permissions around execution, rechecks the preregistered attack inventory, and
derives Q1–Q5 from typed report fields. It does not accept either
implementation's authored question outcomes.

## 2026-09-03 — Registered execution retained

Executed both implementations for ten repetitions. Their complete canonical
model reports were byte-identical. All 23 attacks rejected exactly; all 16
preflight authority attacks stopped before workload entry; all 12 observations
had unique declarations; all 15 declarations had observed or unused
dispositions. The hidden policy change invalidated in 10/10 runs, the unrelated
control invalidated in 0/10, and both representative outputs matched their
frozen identities without changing any fixture.
