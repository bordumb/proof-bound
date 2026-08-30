# Canonical artifact-checker template

Use this template when a public claim is about the meaning of exact published
bytes. The included Rust crate implements a small, bounded `PBCT` envelope; it
is a format scaffold, not an application-specific proof.

## Boundary to preserve

An artifact-bound claim needs separate records for separate facts:

1. a theorem evidence record audits the exact public declaration named by
   `unit.theorem`;
2. a canonical-artifact record independently checks the artifact bytes,
   schema, literal claim, digest, canonical re-encoding, and trailing-byte
   rejection and points back to that exact theorem evidence record; and
3. an independently implemented checker can also provide diagnostic agreement without
   being promoted to a proof.

The manifests in `manifests/` model those three units separately. Replace all
`EXAMPLE-*`, `YourProject.*`, and `path/to/*` values before registering them in
`proofbound.toml`. Do not fill `statement_sha256` or an artifact digest by hand:
seal values emitted by the compiled auditor and canonical artifact tooling.

## Checker contract

`rust/` accepts exactly the grammar in [`FORMAT.md`](FORMAT.md). It rejects
oversized input before allocation, short input, an unknown version, nonzero
reserved flags, empty or oversized payloads, and trailing bytes. The fixed
width length field and exact-consumption rule give every accepted payload one
encoding; the checker never repairs or rewrites untrusted input.

After copying the template:

```sh
cargo test --manifest-path path/to/checker/Cargo.toml
cargo fmt --manifest-path path/to/checker/Cargo.toml -- --check
```

Write `canonical_artifact_checker.py` from `FORMAT.md`; do not make it a
source-text scanner or a wrapper that merely trusts another command's exit
code. Its two-argument artifact mode must consume the certificate and a
committed binding expectation and emit canonical JSON using schema
`proofbound-artifact-check-result/1`, including the exact theorem declaration,
claim and artifact inventories, actual SHA-256, and all six checked binding
facts. In Lean, implement an independent byte decoder, prove the generic
acceptance-implies-meaning helper, and use it in the claim-attributed
`publishedArtifactSoundness` theorem. Both evidence manifests name that exact
declaration, while the theorem audit and byte checker remain distinct records.
Write the diagnostic `independent_checker.py` separately from that canonical
checker (and from the Rust/Lean implementations) if you retain the optional
independent evidence unit.

## Publication checklist

- The input bound is enforced before attacker-controlled allocation.
- Every accepted byte string round-trips byte-for-byte.
- Unknown versions, reserved values, truncation, and trailing data fail closed.
- The public theorem carries `@[proofbound_claim "EXAMPLE-ARTIFACT-001"]`.
- Other theorems on the registered public surface have reviewed
  `proofbound_exempt` reasons.
- The compiled declaration inventory and exact axiom set match the manifests
  bidirectionally.
- The published artifact identity comes from the tool; no placeholder hash is
  accepted.
