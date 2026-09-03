# WS-AC: source-to-artifact correspondence

- **Status:** bounded dual-compilation result; machine-code correspondence open
- **Hypothesis:** H7
- **Depends on:** WS-IR artifact and assumption semantics
- **Blocks:** credible native release claims

## Objective

Compare verified compilers, proof-producing compilation, translation
validation, deterministic compilation, dual compilation, WebAssembly targets,
and reproducible builds with explicit compiler assumptions.

## Current evidence

EXP-LANG-007 binds one canonical source to exact research bytecode through two
independent compilers and validates every artifact byte in two independent
VMs. The result deliberately reports `artifact_proved=false`: dual compilation
is correspondence evidence, not a verified-compiler theorem. Machine code,
optimizing compilation, and production release artifacts remain untested.

## Exit criteria

Source proof and artifact correspondence remain distinct; every trusted
compiler component is visible; relevant build changes invalidate the binding;
reports never shorten “source proved, compiler assumed” to “artifact proved.”
