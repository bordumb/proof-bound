# WS-DSL: typed assurance DSL

- **Status:** running bounded frontend experiment; production adoption remains blocked by Gate 1
- **Hypothesis:** H4
- **Depends on:** WS-IR, WS-EA, WS-IN
- **Blocks:** ergonomic native-language surface research

## Objective

Test whether typed modules, patterns, and diagnostics improve assurance
authoring beyond replacing TOML punctuation.

## Planned comparison

Compile equivalent TOML, restricted typed-configuration, and custom DSL
frontends into byte-identical Assurance IR and compare authoring and review.

## Active experiment

[EXP-LANG-004 / Experiment 0011](../../../experiments/0011-dual-frontend-equivalence/README.md)
compares current TOML, a small Proofbound research DSL, and Pkl 0.32.1 over
three frozen programme slices. It targets a research-only frontend IR and does
not treat byte equality as dependency completeness after EXP-LANG-003.

## Exit criteria

Meaningful errors fail before execution, duplication falls in real projects,
and users can inspect the deterministic effective programme.

## Stop condition

Retain existing manifests if the DSL changes syntax but not semantic safety or
reviewability.
