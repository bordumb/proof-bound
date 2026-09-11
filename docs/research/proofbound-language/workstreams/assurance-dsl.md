# WS-DSL: typed assurance DSL

- **Status:** bounded experiment concluded; confirmatory claim invalid, production adoption blocked
- **Hypothesis:** H4
- **Depends on:** WS-IR, WS-EA, WS-IN
- **Blocks:** ergonomic native-language surface research

## Objective

Test whether typed modules, patterns, and diagnostics improve assurance
authoring beyond replacing TOML punctuation.

## Planned comparison

Compile equivalent TOML, restricted typed-configuration, and custom DSL
frontends into byte-identical Assurance IR and compare authoring and review.

## Concluded experiment

[EXP-LANG-004 / Experiment 0011](../../../experiments/0011-dual-frontend-equivalence/README.md)
compared current TOML, a small Proofbound research DSL, and Pkl 0.32.1 over
three frozen programme slices. Independent Rust and Python implementations
agreed exactly across all nine pairs and rejected all 22 attacks. Both typed
frontends cleared the assignment-reduction threshold for Python and
TypeScript.

The result does not authorize adoption. Cross-frontend receipts correctly
differ because provenance differs, eight semantic attacks lacked source spans,
and all three frozen hash controls were wrong despite correct byte lengths.
The experiment retained those controls and marked itself non-confirmatory.

## Findings

- Common effective meaning and frontend-specific provenance require separate
  identities.
- Typed abstraction reduced repetition in two smaller slices, but not by the
  registered threshold in the larger Rust slice.
- A typed parser is insufficient for language-quality diagnostics unless
  source origins survive normalization and join validation.
- Pkl can be authority-bounded for this corpus, but its evaluator identity and
  policy remain part of the trusted frontend dependency closure.

## Exit criteria

Meaningful errors fail before execution, duplication falls in real projects,
and users can inspect the deterministic effective programme.

## Stop condition

Retain existing manifests until a newly preregistered experiment has valid
controls, source-aware semantic diagnostics, and a criterion that compares
effective meaning without erasing provenance.
