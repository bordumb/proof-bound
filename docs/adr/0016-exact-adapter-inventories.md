# ADR 0016: Make adapter inventories exact and executable

Status: accepted

## Context

The reference pilots exposed a common failure mode across otherwise unrelated
tools: a zero process exit did not establish which semantic units were actually
selected. In experiment 0003, Charon accepted an inherent-method selector but
produced an empty translation inventory (EXP-0003-D02). Kani metadata and test
collection had stronger discovery surfaces, but gaps remained at their wire
boundaries: a duplicate source key in raw `standard-harnesses` JSON could be
collapsed by ordinary map deserialization; loose runner-summary matching could
mistake substrings for one selected pass; and an independent checker could
return zero without reporting the registered set.

The protocol also did not state one response meaning for each operation. An
`inventory` request could be treated as a cheap manifest echo even for a route
whose only authoritative inventory is produced by executing a checker or
round trip. Generator verification had the related problem of asking a program
to inspect committed outputs rather than demonstrating that it can reproduce
them from an output-free state. Public schemas compounded the ambiguity by
requiring a nonempty inventory for every passed record, including
compiler-internal derivations with no observed target selection, while not
constraining the exit and truncation facts of passed process runs.

These are assurance-boundary problems, not subject-project exceptions. An
inventory can support evidence only when it is the exact result of the
registered selection mechanism and is compared in both directions; discovery
alone is not assurance evidence.

## Decision

Adopt specification 0.10.0 and the following common rules.

### Operation responses

- `doctor` probes registered tools and capabilities. Success returns null
  evidence and an empty inventory.
- `inventory` runs the route's authoritative discovery and exact registration
  comparison. Success returns null evidence and the exact nonempty canonical
  inventory. Discovery is not admitted as claim evidence.
- `check` and `reproduce` perform discovery plus the registered assurance
  action. Success returns passed evidence and the same exact nonempty
  inventory. `reproduce` is distinguished at the orchestrator boundary by
  exact-unit selection and cache bypass, not by weaker adapter behavior.
- `update` is write-capable only for a route with a declared output allowlist.
  It never returns passed evidence. Null is preferred; a route-specific drifted
  record is non-admissible review information until a later check passes.
- Failure always returns null evidence, an empty inventory, and a stable
  bounded diagnostic.

A protocol inventory is a strictly increasing lexical set. Every item remains
nonempty after Unicode trimming, contains at most 4096 Unicode characters, and
contains no Unicode control character. Implementations enforce exact ordering
and bidirectional registration equality in addition to the public schema's
length, lexical, and uniqueness constraints.

### Passed process evidence

A passed adapter observation always has a nonempty exact inventory. A passed
canonical evidence or receipt record requires a nonempty inventory only when
`provenance.execution_kind` is `observed-processes`. Every run retained by a
passed observed-process record has `exit_code = 0` and
`output_truncated = false`.

The conjunction is intentional. A compiler-internal derivation has no observed
process or tool-selected target and may carry an empty inventory. A non-passing
record may retain a failed run and empty or partial inventory for diagnosis;
those facts do not support a claim.

### Route-specific discovery

- Kani requires `kani-list.json` to be absent before `cargo kani list`, then
  accepts only the fresh bounded regular package-local file. Raw duplicate keys
  inside `standard-harnesses` are rejected before map deserialization can
  collapse them. The standard-harness inventory must be nonempty, agree with
  metadata totals and executable version, and equal the registered harness set.
  Contract harnesses remain unsupported. Inventory stops after discovery;
  check and reproduce additionally run the exact registered harness vector.
- Cargo/libtest and pytest collect authoritative nodes and match them exactly to
  registration. Check and reproduce invoke each selected node alone and parse
  one anchored one-pass runner summary; test-authored output cannot substitute
  for that summary.
- Canonical-artifact, independent-check, generator, and trusted-transcription
  routes have no weaker metadata-only inventory. Their inventory operation runs
  and parses the same connected checker, fresh reproduction, or round trip used
  to establish the set, but discards the process observation because inventory
  is non-assurance.
- Generator inventory, check, and reproduce assemble a fresh candidate from
  the exact registered non-output inputs, leave every declared output absent,
  invoke the generator with the adapter-owned `--update` switch, and compare
  the complete resulting path-to-bytes map with committed outputs. Only update
  runs the switch in the sealed write-capable project shadow.

### Checker and translation wires

Add the closed `schemas/checker-result.schema.json` success ABI. Canonical
artifact results use `proofbound-artifact-check-result/1` and contain exactly
`schema`, `accepted`, `artifact_logical_name`, `artifact_sha256`, and
`inventory`. Independent results use
`proofbound-independent-check-result/1` and contain exactly `schema`,
`accepted`, and `inventory`. `accepted` is the constant true. The adapter
requires one compact canonical JSON value with no trailing bytes, independently
recomputes artifact identity where applicable, and rejects missing, extra, or
duplicate inventory. Failure output is not part of this success ABI.

Advance translation manifests to `proofbound-translation-unit/3`. Version 2
registered selector roots and output maps but not the full transitive semantic
selection. Each invocation now registers the exact typed
`translated_closure` of supported, non-opaque local functions and types. The
adapter compares the full report closure bidirectionally and rejects empty,
missing, extra, duplicate, cross-kind, external, opaque, unsupported, or
ambiguous selection even when Charon and Aeneas exit zero. The portable
inventory is the strict lexical set of `function:<rust-name>` and
`type:<rust-name>` entries.

## Rejected alternatives

- Treating exit code zero as selection evidence leaves silent skips invisible.
- Returning manifest `expected_inventory` without executing authoritative
  discovery proves only that the manifest can repeat itself.
- Allowing inventory to create admissible evidence conflates target discovery
  with the registered assurance action.
- Verifying a generator against outputs already present permits a no-op or
  self-inspection path to pass without reproducibility.
- Accepting arbitrary checker JSON or checker-authored linkage fields delegates
  Proofbound's claim admission decision to the component being checked.
- Retaining translation-unit version 2 and inferring transitive closure from
  roots recreates the empty-selection failure that motivated the change.

## Consequences

EXP-0003-D02 is fixed by product work rather than rewritten historically: the
pinned experiment remains evidence that the earlier boundary failed, while
version 0.10 rejects that result. Inventory can cost as much as running a
checker, generator, or transcription because some tools expose no independent
authoritative discovery API. That cost is explicit and preferable to a cheap
non-observation.

The wire contract is stricter and some previously accepted records become
invalid: passed observed-process records with empty inventory, nonzero exits,
or truncated output; checker stdout with extensions or trailing whitespace;
Kani metadata with duplicate raw source keys; and translation-unit version 2.
Compiler-internal passed records remain representable without invented targets
or process facts.
