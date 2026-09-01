# WS-DSL: typed assurance DSL

- **Status:** blocked by Gate 1
- **Hypothesis:** H4
- **Depends on:** WS-IR, WS-EA, WS-IN
- **Blocks:** ergonomic native-language surface research

## Objective

Test whether typed modules, patterns, and diagnostics improve assurance
authoring beyond replacing TOML punctuation.

## Planned comparison

Compile equivalent TOML, restricted typed-configuration, and custom DSL
frontends into byte-identical Assurance IR and compare authoring and review.

## Exit criteria

Meaningful errors fail before execution, duplication falls in real projects,
and users can inspect the deterministic effective programme.

## Stop condition

Retain existing manifests if the DSL changes syntax but not semantic safety or
reviewability.
