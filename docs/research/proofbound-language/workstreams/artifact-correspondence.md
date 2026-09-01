# WS-AC: source-to-artifact correspondence

- **Status:** planned
- **Hypothesis:** H7
- **Depends on:** WS-IR artifact and assumption semantics
- **Blocks:** credible native release claims

## Objective

Compare verified compilers, proof-producing compilation, translation
validation, deterministic compilation, dual compilation, WebAssembly targets,
and reproducible builds with explicit compiler assumptions.

## Exit criteria

Source proof and artifact correspondence remain distinct; every trusted
compiler component is visible; relevant build changes invalidate the binding;
reports never shorten “source proved, compiler assumed” to “artifact proved.”
