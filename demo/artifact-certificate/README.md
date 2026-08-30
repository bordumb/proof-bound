# Artifact-certificate demo

This is the self-contained teaching vertical for Specification 0001's
canonical artifact-soundness pattern. It identifies the consumer boundary from
which framework mechanisms should be extracted. The bootstrap built this demo
and the framework core in the same uncommitted pass, so it is not historical M2
before-core evidence; [ADR 0001](../../docs/adr/0001-bootstrap-ordering.md)
records that limitation.

The published artifact is `fixtures/valid-basic.pbac`, 17 canonical bytes with
SHA-256:

```text
dd7cf87ba3535aad431c473b71286fb6806fcc785fc3b39290c4a99d561dfe2d
```

Its three entries are `(1, 3)`, `(4, 128)`, and `(9, 890)`. Their exact sum is
the stated target, `1021`. `FORMAT.md` is the complete bounded, versioned binary
contract.

## Assurance boundary

```text
untrusted fixture producer
          |
          v
 canonical PBAC bytes
     /           \
    v             v
Rust checker   Lean byte-list decoder ----> checkList_sound
    |             |                              |
Python diagnostic|                              v
    |             +---- SHA-256 digest ----> artifact meaning
    +--- fixture agreement
```

The Rust checker and Python diagnostic were independently written from
`FORMAT.md`; neither is generated from, imports, or invokes the other. Lean has
its own parser and ULEB128 implementation. The fixture generator is outside all
three trusted checking paths.

Both non-Lean implementations reject oversized input before an attacker can
force an unbounded read. All checkers reject unsupported versions, reserved
flags, zero or excessive counts, nonminimal and overflowing ULEB128 values,
out-of-range values, zero/unsorted/duplicate IDs, truncation, trailing bytes,
and incorrect sums. The committed corpus includes each important failure class
and a maximum-entry boundary example.

## Claims and trust

| Claim | Formal declaration | Project axioms | Binding evaluation |
|---|---|---|---|
| `PBAC-SUM-001` | `ProofboundArtifactDemo.Claims.publishedTotal` | none | native SHA-256 |
| `PBAC-CALIBRATED-001` | `ProofboundArtifactDemo.Claims.publishedCalibratedTotal` | `providerMeasurementsAccurate` | native SHA-256 |

`publishedTotal` and the generic `checkList_sound` theorem are kernel-checked
and axiom-free. `publishedAccepts` also reduces in the kernel. The literal
SHA-256 computation is the one deliberately native step:
`publishedDigestIsSha256` uses `native_decide`. Consequently the theorem units
say `evaluation_mode = "kernel"` while the artifact-soundness units say
`evaluation_mode = "native"`; the binding is not silently presented as pure
kernel evaluation.

The manifests keep the evidence taxonomy split: each claim cites one `theorem`
unit for its public kernel-checked theorem and one distinct
`artifact-soundness` unit for the native byte/digest binding. The latter runs
the Python checker with a claim-specific committed `*.binding.json`
expectation. Its canonical JSON report names the exact `unit.theorem`, actual
artifact digest, claim and artifact inventories, and explicit results for
canonical payload, schema, literal claim, digest, re-encoding, and
trailing-byte rejection. The orchestrator accepts that report only when the
named theorem resolves uniquely to the separately cited theorem evidence
record. Thus the formal and linkage facets do not derive from a conflated
record or fabricated default flags.

The second claim says more than certificate arithmetic can establish. Its
external-provider premise is therefore a real Lean axiom and a first-class
record in `assumptions/`. Removing that assumption from the claim while leaving
the theorem/evidence unchanged fails manifest cross-validation.

## Reproduce

From the repository root:

```text
cargo test -p artifact-certificate-checker
python3 -m pytest -q demo/artifact-certificate/python/tests
lake build ProofboundArtifactDemo
lake exe proofbound_lean_audit ProofboundArtifactDemo.Claims \
  --surface=ProofboundArtifactDemo.Claims
python3 demo/artifact-certificate/scripts/update_fixtures.py
```

The fixture script is verify-only when invoked directly. Deliberate regeneration
goes through its registered output boundary:

```text
cargo run -q -p proofbound-cli -- update pbac-fixture-generation
```

That command alone may pass the script's private write switch, and imports only
the exact fixture files declared by the unit after running in a sealed shadow.
Review the resulting diff and rerun the verify-only gates. The two diagnostic
CLIs are:

```text
cargo run -q -p artifact-certificate-checker --bin artifact-certificate-check -- \
  demo/artifact-certificate/fixtures/valid-basic.pbac
PYTHONPATH=demo/artifact-certificate/python python3 -m artifact_certificate.checker \
  demo/artifact-certificate/fixtures/valid-basic.pbac
```

## Compiled attribution and pre-core note

Both public theorems carry the root `proofbound_claim` attribute. Every other
theorem on `ProofboundArtifactDemo.Claims` carries a reviewed
`proofbound_exempt` reason. The compiled audit discovers both claims, reports no
axioms for `PBAC-SUM-001`, reports exactly
`ProofboundArtifactDemo.Claims.providerMeasurementsAccurate` for
`PBAC-CALIBRATED-001`, and rejects any unattributed theorem on that surface.

The claim, assumption, and evidence-unit TOML records conform directly to the
root `schemas/claim.schema.json`, `schemas/assumption.schema.json`, and
`schemas/evidence-unit.schema.json`. The demo-local validator additionally
checks cross-references, fixture digests, path safety, and assumption drift.
The claim manifests contain the exact compiled declaration names,
`lean-expr-cbor/1` encoding identifier, canonical statement digests, and
expected axiom inventories. The Lean adapter checks the complete attributed
inventory bidirectionally; no placeholder hash is fabricated.

Extraction candidates are the bounded envelope reader, stable rejection
vocabulary, strict manifest cross-linking, fixture reproduction policy, and
digest-conjoined Lean theorem combinator. Domain semantics—the entry sum and
calibration premise—must remain in this demo.
