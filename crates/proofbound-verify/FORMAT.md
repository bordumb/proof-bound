# Proofbound compiled release receipt v3

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
{"payload":"compiled-receipt.json","payload_sha256":"sha256:<64 lowercase hex>","schema":"proofbound-release-envelope/3"}
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
| compiled payload | `proofbound-compiled-release/3` |
| graph | `proofbound-graph/1` |
| evidence record | `proofbound-evidence/3` |
| source-closure record | `proofbound-source-closure/1` |
| evidence cache material | `proofbound-cache-key/1` |
| registered mutation identity | `proofbound-mutation/2` |

`sealed_files[].sha256` and closure-member hashes are ordinary SHA-256 over
the exact file bytes, still rendered as `sha256:<64 lowercase hex>`.

## Compiled payload

The payload schema is `proofbound-compiled-release/3` and contains exactly:

| Field | Meaning |
|---|---|
| `project`, `project_revision` | non-empty release identity |
| `project_tier` | integer `0`, `1`, `2`, or `3` |
| `tree_state` | `clean` for a portable release |
| `graph`, `graph_sha256` | complete typed graph and its domain hash |
| `claims` | `proofbound-claim/1` internal `statement`, separately optional reader-facing `public_language`, optional claim-tier ceiling, citations, assumptions, bounds, and primary linkage choice |
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
an explicit execution kind, its permitted command/run shape, normalization
identity, timing, deterministic result, configuration, cache key, reuse link,
budget, and actual cost. The verifier recomputes both the evidence wrapper hash
and cache key.
Input and generated artifact inventories are arrays of complete
`{logical_name, sha256, size_bytes}` identities, strictly sorted by that tuple,
with each logical name occurring once. The cache material retains the complete
input identities; it does not discard artifact sizes.

`provenance.execution_kind` is required. `observed-processes` requires nonempty
`provenance.commands` and `provenance.runs` arrays with identical length. Run
position `i` must carry `command_index: i`; no representative command,
reordered run, omitted run, or truncated output is accepted. Ordinary passing
evidence requires every run to exit zero. The sole exception is a versioned
mutation witness: its one typed `expected_failure` run must retain exit 101,
while every other run, including its baseline witness, must exit zero.
`exit_code` is always present and nullable so an incomplete non-passing process
is still represented explicitly. Each command keeps its own bounded, uniquely
named environment allowlist. Every environment entry has a required nullable
`value_sha256`, never a raw value.

`compiler-internal` means the evidence was derived without a subprocess and
requires both command and run arrays to be empty. A compiler-internal record
cannot fabricate process provenance. For both execution kinds, the separately
typed `reproduction_command` remains required and `normalization` is a required
nonblank identifier.

The declared `resource_budget.memory_bytes` is always numeric. In contrast,
`actual_cost.memory_bytes` is required but nullable: an integer, including
zero, is an observed peak; `null` means that peak memory was not measured.
Omitting the field is invalid and a budget is never substituted for an unknown
measurement.

Kind-specific requirements include compiled theorem identity and axiom audit,
the complete `lean-expr-cbor/1` statement wire, theorem-derived artifact
binding, content-derived trusted transcription,
deterministic source refinement with registered premises, explicit bounded
domains/harnesses, the registered solver, exact nonzero per-harness unwind
bounds, the exact ordered unique nonblank bounded-solver assumptions (including
the required empty-array case), exact exhaustive cardinality, independently
inventoried checks, and mutation identities. Detail blocks or mode qualifiers
on the wrong kind are invalid.

An `artifact-bound` policy admits a binding only when all of the following
hold: the referenced theorem is admitted under the policy's theorem-evaluation
mode; the verifier independently reproduces `statement_sha256` from the full
canonical statement wire; that elaborated statement has the exact outer head
`Proofbound.Artifact.DigestBindingV1` with exactly six arguments and direct
string literals for claim ID, artifact schema, logical name, and digest; the
literal claim ID is the current claim; the literal logical name and digest
equal `artifact_binding.artifact`; and that complete artifact identity,
including `size_bytes`, equals exactly one provenance input. A forged size
therefore fails closed. A checker-authored boolean cannot confer
`ARTIFACT_BOUND`. Wrappers,
aliases, nested markers, nonliteral identity fields, and mismatched statement
hashes fail closed. Composing `native-evaluated` narrows the artifact binding
to native mode as well.

`TheoremReceipt` requires `statement_wire` in addition to its
encoding and digest. The v2 `ArtifactBindingReceipt` is exactly
`{"theorem_evidence": ..., "artifact": {"logical_name": ..., "sha256": ...,
"size_bytes": ...}}`; the six v1 checker-authored binding booleans are not
accepted. Release-envelope, compiled-release, and evidence v1/v2 inputs are
rejected rather than guessed or migrated by the verifier.

A trusted-transcription detail is the nested, versioned
`proofbound-trusted-transcription/1` record. Its provenance input inventory is
exactly `{source, committed_transcription, driver}` and its generated inventory
is exactly `{transcribed_candidate, reencoded_source}`; all five logical names
are distinct. Every reference is a complete artifact identity. The verifier
requires candidate digest and size to equal the committed transcription, and
re-encoded digest and size to equal the source. Thus both legs are derived from
observed bytes rather than a `round_trip_passed` boolean, which is not part of
the wire format and is rejected as an unknown field.

The nested record also carries `transcriber` and `reencoder` subrecords with a
TCB node and role identity. For each role, the verifier independently computes
`sha256(proofbound-transcription-tcb-role/1 || NUL || canonical({abi, driver,
role}))`, where `abi` is `proofbound-transcription-driver/1`. The two identities
and nodes must differ. Node IDs are fixed to
`tcb:trusted-transcription:<unit-without-unit-prefix>:<role>`. The sealed TCB
ledger must contain the corresponding unit-scoped components named
`trusted-transcription/<unit-without-unit-prefix>/<role>`, with the ABI as
version and the recomputed role digest as identity. This permits two units with
different drivers without collapsing their trust identities.

A mutation witness is the nested `proofbound-mutation-witness/2` record. It
names exactly one lowercase mutation ID, and the outer target inventory must be
that singleton. The outer unit ID must be exactly `unit:<mutation-id>`. Every
affected outer claim must bind the subject node independently derived as
`subject:<sha256(raw mutation subject)>`. Its four provenance inputs are
exactly the registry, target preimage, registered mutant artifact, and witness
source; its only generated artifact is the replayed target postimage. The
target preimage's path, digest, and size must identify exactly one member of
the referenced semantic closure. The preimage and postimage keep the same
logical target but different bytes, while the postimage bytes exactly equal
the separately registered mutant artifact. No extra input, generated artifact,
mutation, or affected claim can be smuggled into the evidence unit.

`baseline_run_index` binds the clean witness execution and
`expected_failure.run_index` binds the later mutant execution. The former must
exit 0 and the latter must exit 101; `{101}` is the complete allowed-exit set,
and no other nonzero run is accepted. Both commands independently select the
same exact test with `[<selector>, "--exact"]`, carry the same environment
allowlist, and name distinct shadow-built executables so the clean binary
cannot be replayed as the mutant. The verifier independently recomputes
`mutation_sha256` as
`sha256(proofbound-mutation/2 || NUL || canonical(material))`, where `material`
contains `mutation_id`, `subject`, `guard`, `check_id`, the complete four input
artifact roles, the postimage, and the outer claim set. Run positions and proof
term classification are deliberately excluded from registration identity;
they are separately bound by the evidence receipt and policy logic.

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

The immutable Tier-1 `transcribed` profile requires valid
`trusted-transcription` evidence and `TRANSCRIBED` linkage, but no theorem. The
record therefore leaves the formal facet `OPEN` unless separate evidence earns
a formal standing. Trusted transcription itself can never yield `PROVED` or
`ARTIFACT_BOUND`; attempting either upgrade is a status mismatch.

Every field in `reported_statuses` must equal the recomputed value. Its required
`public_statement` is independently derived from `public_language` when
present, otherwise from the internal `statement`; `BOUNDED_CHECKED` and
policy-admitted exhaustive `PROVED` output append
` Registered finite domain: <registered_domain_language>`. The verifier
deliberately rejects substitution of the internal and reader-facing languages,
status drift, upgrades, and unexplained downgrades so a receipt has one
deterministic representation.

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
