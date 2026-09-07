# Release verification

A Proofbound release contains its compiled graph, evidence records, source and
toolchain closures, assumption and TCB ledgers, schemas, demo receipts, binary
checksums, and build provenance.

Run:

```console
proofbound-verify --release /path/to/release
```

The verifier executes no external tools. It checks canonical identities and
closure membership, requires the sealed TCB ledger to equal the tool and
adapter identities recomputed from evidence, reconstructs claim evidence, and
recomputes facets. A successful result means the release is
**receipt-consistent**. It does not mean the verifier independently observed
Lean, Kani, a compiler, or a human review.

For a v4 release with exact artifact observations, sealed artifact and
procedure bytes are checked automatically. Supply unsealed bytes with a closed
manifest:

```console
proofbound-verify \
  --release /path/to/release \
  --observation-inputs /path/to/observation-inputs.json
```

Without every required byte stream, a valid v4 receipt is
`record-consistent` and publication remains blocked. Once the verifier hashes
every artifact and procedure to the identities in the reconstructed relation,
the verdict is `bytes-observed`. This does not promote `TESTED` to `PROVED` or
`MODEL_ONLY` to `ARTIFACT_BOUND`.
