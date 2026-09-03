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

## 2026-09-03 — Candidate implementations completed

Implemented the bounded frontend model independently in Rust and Python. Each
implementation parses the selected TOML documents and custom DSL, consumes
restricted Pkl-rendered JSON, normalizes set and record order, validates typed
evidence/claim joins, emits a standalone effective programme and total source
map, binds frontend dependencies, and derives the research receipt.

The custom formatter is byte-idempotent, although the already-frozen `.pb`
sources were not in its lexical assignment order. Formatting changes only the
authoring bytes: compilation before and after formatting has the same meaning.

During implementation, two initially permissive checks were corrected before
execution: stable IDs now reject mixed-case aliases, and source-map entries
must name both a bound dependency and the deterministic source appropriate to
their frontend and semantic record.

## 2026-09-03 — Execution concluded

Ran all nine project/frontend pairs ten times. Each repetition used the Rust
compiler and the independently written Python compiler. Pkl repetitions used
the exact registered 0.32.1 macOS ARM executable with only `PATH=/usr/bin:/bin`,
the registered local module root, no resources, no cache, and the ten-second
per-process limit. All nine Rust/Python compilation pairs were byte-identical,
and all positive outputs were deterministic.

All 22 attacks rejected with the preregistered code in both implementations.
The four Pkl source-authority attacks and the DSL unknown-field attack retained
nonempty source spans. Eight semantic attacks were executed against canonical
post-parse programmes and therefore had no frontend source span; this falsifies
Q2's stronger diagnostic criterion even though rejection was exact.

The frozen control then exposed a preregistration defect. Canonical byte lengths
match all three registrations exactly, but observed domain-separated identities
are:

- Python: `sha256:6c8acad7f1c5bbbfc6aa22fb585967d729d6320ae8b0437a7d78fa7b04fb8a70`;
- TypeScript: `sha256:61235f3f7df9d68f9b99b88b3d986e4cc1e6f24f9bd40710f29967187e3afc39`;
- Rust: `sha256:e23b5451b4381b6ac829ff9807084eeb44a1c64a4faab7705d5cf6d98d19005a`.

None matches the corresponding frozen hash. The independent implementations
agree on the observed identities, so the mismatch is in the pre-implementation
control, not an implementation disagreement. The frozen corpus was not edited.
This makes the experiment non-confirmatory.

Q1 also fails literally because the preregistration demanded identical receipts
across frontends while the registered receipt model includes `frontend`, source
map, and dependency identities. Those fields necessarily and correctly differ.
Q3, Q4, and Q5 pass their bounded criteria. Q2 fails. Production adoption is
not authorized.
