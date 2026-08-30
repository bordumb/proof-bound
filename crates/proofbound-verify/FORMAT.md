# Proofbound compiled release receipt v1

This document is the handoff contract between a release producer and the
standalone `proofbound-verify` binary. The authoritative field types are the
public, `deny_unknown_fields` Rust data types in `src/format.rs`. The verifier
has no dependency on the orchestrator or any other `proofbound-*` crate and
does not run external tools.

## Directory layout

```text
<release>/
  release.json               # canonical ReleaseEnvelope
  compiled-receipt.json      # canonical CompiledRelease (name is selectable)
  ...                        # optional files named by sealed_files
```

`release.json` has exactly this shape:

```json
{"payload":"compiled-receipt.json","payload_sha256":"sha256:<64 lowercase hex>","schema":"proofbound-release-envelope/1"}
```

`payload` is a normalized relative path. Absolute paths, `.`/`..`, duplicate
separators, backslashes, control characters, and symlinks are rejected.

## Canonical JSON and hashes

Both JSON files use UTF-8 compact JSON with no trailing newline and object
keys sorted recursively in ascending Unicode/UTF-8 order. Array order is
preserved. Sets in the Rust format serialize as sorted arrays. Unknown object
fields and unknown enum values are rejected.

The canonical digest function is:

```text
sha256:<lowercase hex SHA256(domain UTF-8 || 0x00 || canonical JSON bytes)>
```

The domains are fixed:

| Value | Domain |
|---|---|
| compiled payload | `proofbound-compiled-release/1` |
| graph | `proofbound-graph/1` |
| evidence record | `proofbound-evidence/1` |
| source-closure record | `proofbound-source-closure/1` |
| evidence cache material | `proofbound-cache-key/1` |

`sealed_files[].sha256` and closure-member hashes are ordinary SHA-256 over
the exact file bytes, still rendered as `sha256:<64 lowercase hex>`.

## Compiled payload

The payload schema is `proofbound-compiled-release/1` and contains exactly:

| Field | Meaning |
|---|---|
| `project`, `project_revision` | non-empty release identity |
| `project_tier` | integer `0`, `1`, `2`, or `3` |
| `tree_state` | `clean` for a portable release |
| `graph`, `graph_sha256` | complete typed graph and its domain hash |
| `claims` | `proofbound-claim/1` raw language, optional claim-tier ceiling, citations, assumptions, bounds, and primary linkage choice |
| `evidence` | content-addressed raw evidence and provenance records |
| `assumptions`, `premises` | `proofbound-assumption/1` records and first-class premises used in transitive closure |
| `policies` | complete effective policy definitions, not just policy names |
| `closures` | content-addressed source-closure inventories |
| `sealed_files` | optional physical file paths, raw hashes, and byte sizes |
| `reported_statuses` | producer output that must exactly equal recomputation |

Every element of `evidence` is
`{"sha256": <evidence-domain-hash>, "record": <EvidenceReceipt>}`. Evidence
citations, artifact/source theorem references, present premise theorem
references, discharge references, and assumption review references all use
that wrapper digest as the evidence identity. A premise may omit
`theorem_evidence` only when it is a direct claim-level premise bound by an
exact `assumes` edge from the applicable claim node to the premise node.
Such an ownerless premise is necessarily undischarged; attaching a `discharge`
to it is invalid. Closure references use the analogous closure wrapper digest.

The graph has closed `node.kind` and `edge.kind` enums. In addition to endpoint
existence and unique IDs, the verifier independently enforces the complete
edge-to-endpoint table from Specification 0001 §6.2; for example, `proves` is
legal only from `theorem` to `claim`, and no edge kind accepts `toolchain` or
`tcb-component` endpoints in schema version 1. A graph cycle is rejected unless
its strongly connected component is exactly one declared mutual-theorem group,
every internal edge is `depends-on`, and every member is a theorem in the
declared proof environment.

## Evidence facts

Each evidence record includes a closed evidence kind, outcome, kind-specific
detail block, and full provenance. Provenance binds the clean project revision,
semantic closure, input/generated artifacts, tool and adapter identities,
commands, timing, deterministic result, configuration, cache key, reuse link,
budget, and actual cost. The verifier recomputes both the evidence wrapper hash
and cache key.

Kind-specific requirements include compiled theorem identity and axiom audit,
strong canonical artifact binding, explicit transcription TCB and round trip,
deterministic source refinement with registered premises, explicit bounded
domains/harnesses, exact exhaustive cardinality, independently inventoried
checks, and mutation identities. Detail blocks or mode qualifiers on the wrong
kind are invalid.

An `artifact-bound` policy admits a strong artifact binding checked explicitly
in either kernel or native mode while its theorem is still admitted under the
policy's theorem-evaluation mode. Composing `native-evaluated` narrows the
artifact binding to native mode as well.

The closed enum spellings are defined by `src/format.rs`: most inputs use
`kebab-case`; the three output facets use `SCREAMING_SNAKE_CASE`. `FlowScope`
and `NativePremiseRule` are internally tagged by `kind`.

## Independent recomputation

For each claim, the verifier computes the transitive closure of direct
citations, evidence assumptions/premises, project axioms, graph `assumes`
edges, assumption dependencies/reviews, theorem premises, and proposed
discharge theorems. A cited missing or non-passing record, invalid digest or
shape, unregistered applicable record, tier violation, or ambiguous primary
linkage makes the claim `INVALID`.

An ownerless premise is included only through its exact claim-to-premise
`assumes` edge. The verifier also rejects every ownerless premise record that
has no such edge from any registered claim, so omitting both the owner and edge
cannot hide an undischarged premise or promote a claim. A proposed discharge
on an ownerless premise is rejected and ignored during status recomputation.

The effective evidence and policy ceiling is the lower of `project_tier` and
the claim's optional `tier`; absence inherits the project tier. A claim tier
above its project tier is malformed and cannot raise the effective ceiling.

Otherwise the formal precedence is admitted theorem, policy-admitted exact
exhaustive check, bounded check, empirical evidence, then open. Linkage is
independently selected from valid source refinement, strong artifact binding,
trusted transcription, or model-only evidence. Premises remain assumed unless
a policy-admitted theorem, an exact `discharged-by` graph edge, and a covering
flow scope all agree. The effective policy is then evaluated for tier, theorem,
linkage, bounded check, assumption, native-premise-count, and additional
evidence requirements.

`ledger` is an immutable built-in component with minimum tier 0. It cannot be
composed with another component or carry theorem/axiom, bounded, or shipping-
linkage requirements. Passing empirical evidence yields at most `TESTED`;
theorem, exhaustive, bounded, and subject-binding records remain visible only
as non-admitted support, so linkage remains `MODEL_ONLY`.
Admission is orthogonal to evidence availability: for example, an independent
check can support a Ledger claim as `TESTED`, but that evidence kind still
requires effective Tier 1.

Every field in `reported_statuses` must equal the recomputed value. The
verifier deliberately rejects both upgrades and unexplained downgrades so a
receipt has one deterministic representation.

Every successful verification report also contains a mandatory
`not_proved_out_of_scope` entry for every claim, including its open
obligations, undischarged premises, explicit assumptions, and registered
exclusions. The human CLI always renders this section, even when every set is
empty.

## CLI and trust boundary

```text
proofbound-verify --release <directory> [--json]
```

Exit `0` means receipt-consistent and policy-admitted. Exit `3` means the
receipt is internally consistent but at least one claim is blocked by policy.
Exit `2` means malformed, tampered, structurally invalid, or inconsistent with
the reported statuses.

The result is only **receipt-consistent**. It checks the relationships and
recorded identities independently; it does not assert that an external prover,
solver, compiler, or test runner executed honestly.
