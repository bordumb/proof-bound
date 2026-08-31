# Proofbound Lean adapter

This adapter turns the compiled `proofbound_lean_audit` result into a strict
Proofbound theorem receipt. It never scans Lean source for attributes,
declarations, axioms, or theorem text.

## Protocol

The process reads exactly one compact, recursively key-sorted JSON request from
stdin and writes exactly one compact, recursively key-sorted JSON response to
stdout. Both envelopes use `proofbound-adapter-protocol/1`; trailing whitespace,
duplicate/unknown fields, invalid request IDs, and oversized input fail closed.
Diagnostics use stable `PB-LEAN-NNNN` codes.

`AdapterRequest.unit` has this shape:

```json
{
  "audit": { "mode": "execute" },
  "claim_inventory": [
    {
      "claim_id": "DEMO-CLAIM-001",
      "declaration": "Demo.Claims.publicTheorem",
      "declaration_kind": "theorem",
      "foundational_axioms": ["Classical.choice"],
      "project_axioms": {
        "Demo.Claims.externalPremise": "DEMO-PREMISE-AX-001"
      },
      "statement_sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "environment_id": "lean:project-toolchain-v1",
  "evidence_unit": {
    "schema": "proofbound-evidence-unit/1"
  },
  "schema": "proofbound-lean-adapter-unit/1"
}
```

The abbreviated `evidence_unit` above stands for the complete strict
`EvidenceUnitManifest`. The adapter accepts only `adapter=lean`,
`kind=theorem`, and `operation.type=lean-audit`, with one target claim and its
exact fully qualified `theorem`.

`claim_inventory` is the complete registered inventory for the modules loaded
by this audit, not merely the target claim. Every compiled attributed claim
must occur exactly once in this array, and every entry must occur exactly once
in compiled output. Declaration name, declaration kind, and the complete
transitive axiom set are compared exactly. A project-axiom map classifies Lean
axiom names as Proofbound assumption IDs; its values must equal the target
unit's assumption list. `sorryAx` is rejected even if someone attempts to
register it.

For an already captured compiled audit, replace the audit member with:

```json
{
  "mode": "captured",
  "output": {
    "claims": [],
    "exemptions": [],
    "schema": "proofbound-lean-audit/1",
    "statement_encoding": "lean-expr-cbor/1"
  },
  "execution": {
    "commands": [
      {
        "args": ["exe", "proofbound_lean_audit", "Demo.Claims", "--surface=Demo.Claims"],
        "environment_allowlist": [],
        "program": "/absolute/path/to/lake"
      },
      {
        "args": ["--version"],
        "environment_allowlist": [],
        "program": "/absolute/path/to/lake"
      }
    ],
    "completed_unix_ms": 2,
    "normalization": "proofbound-lean-command-output/1",
    "resource_usage": {
      "peak_disk_bytes": 0,
      "peak_memory_bytes": null,
      "time_ms": 1
    },
    "runs": [
      {
        "command_index": 0,
        "duration_ms": 1,
        "exit_code": 0,
        "normalized_output_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "output_truncated": false,
        "stderr_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "stdout_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
      },
      {
        "command_index": 1,
        "duration_ms": 0,
        "exit_code": 0,
        "normalized_output_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "output_truncated": false,
        "stderr_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "stdout_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
      }
    ],
    "started_unix_ms": 1,
    "tool": {
      "identity_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "name": "proofbound_lean_audit",
      "version": "Lean 4.x"
    }
  }
}
```

The captured form binds caller-supplied execution provenance; it does not claim
that this adapter launched that earlier process. Execute mode derives the
imported module/public surface from the unit's single typed module-or-theorem
target, binds canonical `.lean` paths as semantic inputs, clears the child
environment, passes only allowlisted variables, enforces the time/output bounds,
and hashes the compiled audit executable. It records the audit command first
and the subsequent `lake --version` identity query second. Both consume one
shared wall-clock budget; the aggregate timestamps and observed time span both
commands and the intervening identity work. Under
`proofbound-lean-command-output/1`, audit stdout normalizes to canonical JSON
and version stdout normalizes to the exact trimmed UTF-8 string retained as the
tool version.

## Statement identity

The adapter validates the array-only ExprWire grammar in
`schemas/lean-expr-v1.cddl`, including universe levels, binder information,
literals, and projections. It rejects free/metavariable encodings, malformed
tags, non-canonical decimal `Nat` transports, excess nesting/size, and trailing
data. It emits definite-length canonical CBOR with shortest unsigned integer
forms and hashes:

```text
SHA-256("proofbound:lean-expr-cbor/1\0" || canonical_cbor_statement)
```

Binder names and source metadata are absent in the Lean-produced wire, so
alpha-renaming cannot change the digest. The configured digest uses the public
manifest spelling `sha256:<64 lowercase hex>`; the typed core receipt's
`Sha256Digest` members use the same prefixed canonical spelling.

## Response and operations

For `check` and `reproduce`, `response.evidence` is exactly a serialized
`proofbound_core::EvidenceRecord`, not an adapter-private observation. A caller
can deserialize the member directly. The theorem detail carries declaration,
encoding, complete canonical statement wire and statement digest, attributed
claim, environment, exact foundational/project axioms,
`contains_sorry_ax=false`, and the evaluation mode.
Provenance binds the Git revision/tree state, exact semantic inputs and output
artifacts, source closure, audit and adapter executable identities, typed
commands and their aligned run records, a required normalization identifier, a
separate typed reproduction command, timestamps, result/configuration
identities, and declared and observed resources. Unknown peak memory is
serialized as required `null`; numeric zero is reserved for a measured
zero-byte peak.

`inventory` runs or consumes the same compiled audit and performs the same
bidirectional declaration/axiom checks but does not create evidence.
`update` intentionally ignores the old statement digest only after every other
check passes, and returns a typed receipt with status `drifted`; the orchestrator
may display its computed theorem digest for review and update the manifest. It
must run a subsequent pinned `check` before the receipt can support a claim.

Core taxonomy keeps artifact soundness separate: this adapter emits theorem
evidence. A canonical-artifact checker must produce a distinct
`artifact-soundness` receipt whose `artifact_binding.theorem` references this
theorem receipt. Statement and axiom facts are never copied into the artifact
record.

## Verification

```text
cargo test -p proofbound-adapter-lean
cargo clippy -p proofbound-adapter-lean --all-targets -- -D warnings
```

The corpus covers alpha-equivalence/name erasure, universe levels, all literal
and projection forms, shortest CBOR integer boundaries, malformed/ambiguous
wire forms, statement drift, duplicate/unknown/missing attributed claims,
declaration-kind and exact-axiom drift, canonical protocol input/output, and
direct `EvidenceRecord` deserialization and validation.
