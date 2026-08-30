# Allowance transfer demo

This is Proofbound's allowance teaching vertical: exact versioned request
bytes enter a pure Rust decision kernel, Python records the runtime byte
submission boundary, and Lean independently models the decoder and transfer
laws. The demo keeps the evidence classes separate instead of calling all of
them “verified.”

```text
registered .bin fixture ──┬──> Rust decoder ──> checked-u64 kernel
                          │                         │
                          │                         ├── Rust tests / mutations
                          │                         ├── registered Kani harnesses
                          │                         └── Charon/Aeneas unit (pending)
                          ├──> Lean byte decoder ──> Nat transfer model / theorems
                          │                              ^
                          │                              │ handwritten refinement
                          └──> Python submitter ──> digest receipt (TESTED only)
```

## Canonical request

`proofbound-allowance-request/1` is exactly 38 bytes. Decoders reject short,
trailing, wrongly versioned, and non-canonical inputs.

| Offset | Width | Meaning |
|---:|---:|---|
| 0 | 4 | ASCII domain separator `PBAL` |
| 4 | 1 | version `1` |
| 5 | 1 | authorization: exactly `0` or `1` |
| 6 | 8 | source balance, unsigned big-endian |
| 14 | 8 | destination balance, unsigned big-endian |
| 22 | 8 | amount, unsigned big-endian |
| 30 | 8 | cap, unsigned big-endian |

The six fixtures in `fixtures/v1` cover acceptance and every denial code. Their
digests and typed meanings are recorded in `fixtures/v1/manifest.json`; Rust,
Python, and Lean each implement their own decoder.

## Decision kernel

`allowance_kernel::decide_transfer` evaluates these observable guards in order:

1. authorization is true;
2. amount is nonzero;
3. amount does not exceed the cap;
4. checked source subtraction succeeds; and
5. checked destination addition succeeds.

Accepted requests return code `0` and the new balances. Denials use stable codes
`1` through `5` and always return the input balances. The Rust crate forbids
unsafe code, has no dependencies, performs no I/O, and uses no ambient state.

Kani receives four `u8` seeds, an authorization bit, and a low/high destination
lane. This is an exact finite domain of `2^34` requests. The high lane maps a
seed to `u64::MAX - seed`, so the bounded checks include fixed-width destination
overflow. The model-check manifest registers every harness by its exact tool
identity; the Kani adapter compares that inventory bidirectionally with
structured `cargo kani list` metadata.

## Claims and current boundary

Seven strict claim manifests live in `claims/`:

| Claim | Intended evidence | Honest current boundary |
|---|---|---|
| `DEMO-TRANSFER-001` | conservation theorem, refinement, Kani, tests | attributed theorem audits cleanly; translation receipt remains open |
| `DEMO-TRANSFER-002` | no-overdraft theorem, refinement, Kani, tests | attributed theorem audits cleanly; translation receipt remains open |
| `DEMO-TRANSFER-003` | cap theorem, refinement, bounded Kani domain | attributed theorem audits cleanly; translation receipt remains open |
| `DEMO-TRANSFER-004` | denial theorem, refinement, Kani, tests | attributed theorem audits cleanly; translation receipt remains open |
| `DEMO-TRANSFER-005` | source-refinement theorem | attributed handwritten bridge theorem audits; generated source binding remains open |
| `DEMO-TRANSFER-006` | independent Rust/Lean decoding | attributed decoder theorem and vectors pass |
| `DEMO-TRANSFER-007` | Python example test and digest comparison | `TESTED`; intentionally never presented as proved |

The open obligations are fields in the claim manifests, not hidden notes. The
six Lean-backed claims bind real `lean-expr-cbor/1` statement digests extracted
from the compiled audit; no placeholder digest or proof receipt is committed.

The source-refinement edge also exposes `DEMO-U64-REP-001`: the handwritten
`Nat` bridge fields must lie inside the translated Rust `u64` carrier. It remains
a visible representation premise until a decoder/adapter theorem discharges it.

## Explicit assumption

`DEMO-IDENTITY-AX-001` states that an external provider's `authorized=true`
response correctly identifies the holder of the source account. The kernel and
Lean model prove consequences of a Boolean input; they do not prove the
provider, operating environment, or human identity correct. Provider execution
of a transfer is out of scope.

## Mutation witnesses

The mutation registry names one deliberately incorrect function and one failing
comparison test for every decision guard. Mutants are compiled only for tests or
with the explicit `mutation-testing` feature. They never replace the shipping
symbol. Removing authorization, positive amount, cap, checked subtraction, or
checked addition visibly diverges from the registered kernel behavior.

## Run locally

From the repository root:

```sh
cargo test -p allowance-kernel
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=demo/allowance/python python3 -m pytest -q demo/allowance/python/tests
lake build ProofboundDemo
PYTHONPATH=demo/allowance/python python3 -m proofbound_demo.allowance
```

The Python command emits canonical JSON with `formal_facet: "TESTED"` and
`evaluation: "empirical-runtime-observation"`. Its default receiver is an
in-process digest endpoint so the example is deterministic; a deployment can
provide another `SubmissionTransport` without moving network behavior into the
kernel.

## Translation quarantine and integration work

`proofbound/translations/transfer-kernel.toml` is authoritative for package,
start symbol, generated destination, bridge, import mapping, determinism, axiom
policy, claims, and resource budget. `lean/Generated/Allowance` is reserved
exclusively for generator output and intentionally contains no handwritten
files. The transparent bridge is outside it at
`lean/ProofboundDemo/Bridges/Kernel.lean` and is byte-pinned by the manifest.
The prospective evidence unit is retained as
`proofbound/evidence/transfer-refinement.toml.example`; it is deliberately not
part of the executable evidence set until the pinned translators are
available. The prospective three-runtime conformance unit is likewise retained
as `canonical-conformance.toml.example`; the active canonical claim currently
cites the independently implemented Rust test and compiled Lean theorem.

Open integration work:

- run the manifest-driven Charon/Aeneas adapter twice and replace the teaching
  bridge's decision body with generated imports;
- promote the example source-refinement unit into the executable evidence set
  only after its deterministic generated output and receipt exist.

The Kani adapter already consumes structured `cargo kani list` JSON and rejects
missing or undeclared harnesses. The unavailable translation lock keeps source
refinement as a visible open obligation; compilation, theorem checking, or
bounded-check success alone does not upgrade the linkage facet to `REFINED`.
