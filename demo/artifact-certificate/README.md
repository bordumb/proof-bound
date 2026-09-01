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
| `PBAC-SUM-001` | `ProofboundArtifactDemo.Claims.publishedArtifactSoundness` | none | native SHA-256, explicit premise |
| `PBAC-CALIBRATED-001` | `ProofboundArtifactDemo.Claims.publishedCalibratedArtifactSoundness` | `providerMeasurementsAccurate` | native SHA-256, explicit premise |

`publishedTotal` and the generic `checkList_sound` theorem are kernel-checked
meaning helpers. The attributed public declarations instead have the exact
outer type `Proofbound.Artifact.DigestBindingV1`: their elaborated statements
contain literal claim ID, artifact schema, logical path, digest, byte value,
and meaning. The SHA-256 field uses `native_decide`, so both the theorem and
artifact-soundness units say `evaluation_mode = "native"`. The custom policies
compose `artifact-bound` with `native-evaluated`, and the first-class
`PBAC-NATIVE-SHA256-001` assumption makes the enlarged trust boundary visible.

The manifests keep the evidence taxonomy split: each claim cites one `theorem`
unit for the typed public theorem and one distinct `artifact-soundness` unit
for checking the external bytes. The latter runs the Python checker with a
claim-specific committed `*.binding.json` expectation. Its canonical JSON
report contains only success, exact artifact identity, and inventory. It still
fails unless parsing, canonical re-encoding, and trailing-byte rejection all
succeed, but it cannot name a theorem or assert binding booleans. Core and the
standalone verifier independently parse the theorem statement wire and join
its literal path/digest to the adapter-recomputed artifact identity.

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

Both typed binding theorems carry the root `proofbound_claim` attribute. Every other
theorem on `ProofboundArtifactDemo.Claims` carries a reviewed
`proofbound_exempt` reason. The compiled audit discovers both claims, reports no
unclassified axioms, reports the exact native-evaluation axiom on each claim,
reports `ProofboundArtifactDemo.Claims.providerMeasurementsAccurate` only for
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
