# WS-FB: foreign and mixed-language boundaries

- **Status:** EXP-LANG-008 concluded with bounded bridge support
- **Hypothesis:** H8
- **Depends on:** WS-NE, WS-AC, existing-language adapters
- **Blocks:** Gate 5

## Objective

Keep Python, TypeScript, Rust, operating systems, databases, and services as
honest permanent foreign components while allowing gradual native replacement.

## Exit criteria

Foreign evidence cannot claim native proof, native and foreign components share
one graph, and migration strengthens only the affected claims without hiding
remaining assumptions.

## Result

Experiment 0017 meets these criteria for one pure packet ABI, two exact
runtimes, and twelve frozen cases. Both foreign applications remain tested;
the native source fact and assumption-bound artifact are separate; all bridge,
runtime, and compiler-correspondence assumptions survive; and the unrelated
claim is unchanged. Arbitrary foreign interfaces and production enforcement
remain outside the supported scope.
