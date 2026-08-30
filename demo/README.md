# Proofbound demonstrations

The two demos show different ways to bind public language to evidence while
keeping the remaining trust boundary visible. Neither demo treats a passing
test, a bounded check, or a theorem over a handwritten model as proof about
shipping code by itself.

## Allowance transfer

[`allowance/`](allowance/) follows canonical request bytes through a Python
submitter and a pure Rust checked-arithmetic kernel into independent Lean
models. It registers conservation, no-overdraft, cap, denial, refinement, and
decoder claims. The runtime byte-submission claim is intentionally `TESTED`,
not proved.

Its real-world authorization language depends on
`DEMO-IDENTITY-AX-001`: an external provider's `authorized=true` response is
assumed to identify the source-account holder correctly. The separate
`DEMO-U64-REP-001` premise keeps the Rust `u64`/Lean `Nat` bridge explicit.

The repository currently pins Charon and Aeneas as unavailable in
`proofbound/toolchains/translation.lock`. Until real revisions and tools are
pinned and deterministic translation is reproduced, the source-refinement
edge remains open; the handwritten Lean relation does not substitute for it.
The same rule applies to bounded Kani evidence when Kani is unavailable.

Run the empirical vertical:

```sh
uv run --frozen cargo run -q -p proofbound-cli -- demo allowance
```

## Artifact certificate

[`artifact-certificate/`](artifact-certificate/) checks a bounded, versioned
binary certificate in Rust, Python, and Lean. Rust and Python reject malformed
or noncanonical envelopes independently; Lean proves a generic
acceptance-implies-meaning theorem and binds the exact published bytes and
digest.

`PBAC-SUM-001` is axiom-free. `PBAC-CALIBRATED-001` deliberately depends on the
first-class `PBAC-CALIBRATION-AX-001` premise because arithmetic consistency
cannot establish that an external provider's physical measurements are
accurate. The theorem record and artifact-soundness record remain distinct.

Run the artifact vertical:

```sh
uv run --frozen cargo run -q -p proofbound-cli -- demo artifact-certificate
```

## Inspect the boundary

After a verify-only check, inspect claims and assumptions through the shared
CLI:

```sh
uv run --frozen cargo run -q -p proofbound-cli -- check --fresh
uv run --frozen cargo run -q -p proofbound-cli -- assumptions
uv run --frozen cargo run -q -p proofbound-cli -- claim PBAC-SUM-001 --graph
```

`proofbound check` may refresh only ignored state beneath `.proofbound/`. It
does not update committed fixtures, generated Lean, manifests, schemas, or
receipts. Deliberate regeneration belongs to `proofbound update`, followed by
review of the diff and the same verify-only gates used in CI.
