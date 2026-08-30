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
