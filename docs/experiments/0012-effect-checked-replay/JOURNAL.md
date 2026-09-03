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
