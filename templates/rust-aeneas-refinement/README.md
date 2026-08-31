# Rust/Charon/Aeneas refinement template

This template starts a source-refinement edge from a small pure Rust function
to a handwritten Lean relation. It does not claim that source refinement has
already happened.

## Layout and ownership

- `rust/src/lib.rs` is the shipping source subject.
- `translation-unit.toml` is authoritative for package, start symbol,
  LLBC filename, complete produced-to-destination output map, two-run
  determinism policy, and resource budget.
- `lean/Generated/` is generator-owned and must be replaced atomically. Never
  preserve handwritten files, readmes, or review notes there. The manifest's
  mapped destinations are the only files the replacement may create.
- `lean/KernelRefinement.lean` is handwritten and stays outside the generated
  tree.
- `representation-premise.toml` keeps the bounded Rust carrier visible when a
  richer Lean model uses natural numbers.

Replace every `EXAMPLE-*` and `YourProject.*` identity before registration.
The example deliberately omits `external_bridges`: if a bridge is required,
put it outside `lean/Generated/`, review it independently, and add the real
tool-computed SHA-256 to the translation manifest. Never paste a made-up hash.
The illustrative `Funs.lean`, `Types.lean`, and `translation.json` mappings are
based on the pinned pilot's output shape, not an observed run of this template.
Before registering the unit, run the pinned tools in a disposable directory
and replace them with this crate's complete exact inventory; an extra, missing,
renamed, or unmapped output is a hard failure.

## Verify-only workflow

1. Pin full Charon and Aeneas revisions in the project translation-toolchain
   lock.
2. Register `translation-unit.toml`, `source-refinement-evidence.toml`, the
   claim, and the representation premise in the project manifest.
3. Run the pinned translation once outside the registered evidence path to
   establish the exact output map, then run
   `proofbound update example-kernel-translation` deliberately and review the
   resulting complete generated-tree replacement.
4. Implement the handwritten theorem against the generated declarations.
5. Run `proofbound check --fresh`; the adapter must translate twice, normalize
   only as declared, compare the outputs byte-for-byte, audit generated axioms,
   and match the compiled claim inventory.

If Charon or Aeneas is absent or unpinned, report the capability as unavailable
and leave the refinement edge open. A handwritten model or theorem alone is
not evidence about the shipping Rust function.

## Representation premise

`EXAMPLE-U64-REP-001` says that values entering the handwritten `Nat` model
remain inside the translated Rust `u64` carrier. Keep the premise on both the
claim and source-refinement evidence until a registered adapter theorem
discharges it.

The sample Rust crate can be checked independently:

```sh
cargo test --manifest-path templates/rust-aeneas-refinement/rust/Cargo.toml
cargo fmt --manifest-path templates/rust-aeneas-refinement/rust/Cargo.toml -- --check
```
