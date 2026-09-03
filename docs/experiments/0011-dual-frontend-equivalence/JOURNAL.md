# Experiment 0011 journal

[Experiment registration](README.md)

Append-only execution notes begin after the preregistration commit. Corrections
are new entries rather than edits to earlier observations.

## 2026-09-03 — Corpus frozen

After preregistration commit `025aec9`, froze the three current TOML programme
slices, an equivalent custom `.pb` source and typed Pkl source for each, the
Pkl template, closed grammar and normalization rules, exact canonical
programme identities, the assignment-count metric, and all twenty-two attack
mutations.

Before any retained compiler implementation, a disposable corpus extractor
confirmed that the three source representations denote the same normalized
values. Pkl 0.32.1 was downloaded from its official macOS ARM release, matched
the preregistered SHA-256, and evaluated all three sources under the registered
local-module, no-resource, no-cache policy. This syntax check is corpus
preparation, not an experimental result: the independent compilers, source
maps, receipts, repeated determinism runs, and attacks do not yet exist.
