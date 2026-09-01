# Proofbound

> Make your software's claims compile.

Proofbound is the reference implementation of Proof-Driven Development. It
registers material software claims, binds them to exact subjects and evidence,
and derives a three-facet status without collapsing proofs, bounded checks,
tests, assumptions, or production linkage into a misleading score.

The normative design is [Specification 0001](docs/specs/0001_initial_spec.md).

## Quick start

```console
$ just bootstrap
$ uv run --frozen cargo run -p proofbound-cli -- doctor
$ cargo xtask preflight
$ cargo xtask release-smoke
```

Install the repository's fast local commit gate once with `just hooks`. It
checks version and changelog metadata, whitespace, Rust formatting, repository
manifests and closures, and focused Python contracts before a commit is
created. Run the same subset directly with `just fast-checks`.

`VERSION` is the product-version source of truth. Bump it and synchronize all
derived Rust, Python, Lean, lockfile, and normative-spec declarations with:

```console
$ just set-version 0.12.0
```

Every released version also needs a dated entry in `CHANGELOG.md`; the local
hook requires a staged version bump and changelog update to travel together.

`doctor` reports optional tool capabilities before the full check. The complete
repository gate additionally requires the pinned Kani verifier; the current
Charon/Aeneas capability is deliberately unavailable and is represented as an
open source-refinement obligation rather than fabricated evidence.

For a new or existing repository, install the `proofbound` binary and run
`proofbound init`. The generated Tier 0 ledger needs no theorem prover or model
checker: it starts with explicit claims, assumptions, ordinary tests, and open
obligations.

## Repository map

- `crates/` contains the Rust assurance compiler, strict manifest reader,
  evidence store, adapters, CLI, independent receipt verifier, and typed
  development-gate runner (`xtask`).
- `lean/` contains small reusable declaration-audit and artifact-boundary
  support. Domain theorems do not live there.
- `demo/allowance/` demonstrates a checked transfer model, exact fixtures,
  bounded Kani harnesses, ordinary tests, and an explicit identity-provider
  assumption. Its Charon/Aeneas source-refinement promotion remains open while
  the translation lock is deliberately marked unavailable.
- `demo/artifact-certificate/` contains the independent byte checker, canonical
  fixtures, and Lean theorems used by the artifact-soundness vertical.
- `schemas/` contains the canonical public data contracts.
- [`docs/`](docs/README.md) indexes the product vision, normative design,
  decisions, guides, experiments, audits, assurance records, and working notes.

Proofbound reports a claim as formal, linkage, and assumption facets such as
`PROVED · REFINED · ASSUMED`. Every human report also includes a mandatory
“not proved / out of scope” section.

## Bootstrap status

The first implementation was built as one uncommitted bootstrap after the
v0.4.0 specification commit. It therefore cannot supply §20's historical
ledger-before-proofs or consumers-before-core evidence. The repository does
not reconstruct commits to imply otherwise; the decision and its limits are
recorded in
[ADR 0001](docs/adr/0001-bootstrap-ordering.md).
Before the first implementation commit, `cargo xtask bootstrap-ci` runs the
exact prospective tree through `just ci` in a disposable unrelated one-commit
repository; that commit is deleted and is never presented as project history.

`just ci` is the local verify-only gate and is a thin alias for the typed
`cargo xtask ci` runner. It runs formatting, linting, unit/schema tests, the
Lean build, and a deterministic release round-trip before any expensive Kani
work. Only after those cheap gates pass does it perform one fresh Proofbound
check; it then seals those same receipts and makes the standalone verifier the
final verdict. Temporary paths and process arguments are constructed as typed
Rust values rather than shell snippets. The gate never invokes `proofbound
update` or accepts regenerated evidence. The Charon/Aeneas adapter is tested
for strict, fail-closed behavior, but no source-refinement receipt is published
while the pinned translator capability is unavailable.
