# ADR 0014: Make translation manifests authoritative

Status: accepted

## Context

Experiment 0002 reproduced the pinned Auths Proof Charon/Aeneas pipeline but
failed its manifest-authority questions. The subject manifest agreed with
package names and expected results while xtask still owned Cargo-manifest
selection, crate and LLBC names, symbol grouping, output-directory layout,
output discovery, and generated-file mappings. Proofbound's version-1
translation manifest repeated the same structural gap: flat global arrays
could not say which values belonged to which invocation, and the adapter
inferred or discovered the remaining values. Its `import_mapping` field was
validated but not executed, and `audited-rewrite` could be selected without a
typed rewrite implementation.

That is not harmless convenience. A successful process exit with a different
selection or an extra generated file can otherwise be reported as the
registered translation. Normalizing generated text before comparison can also
hide a byte-level change to reviewed source. These are EXP-0002-D01 and
EXP-0002-D02, not subject-specific exceptions.

## Decision

Adopt the breaking `proofbound-translation-unit/2` format and specification
0.8.0.

- A typed `charon-aeneas` pipeline contains a non-empty, strictly ordered list
  of invocations. Each invocation owns its ID, exact Cargo package and manifest,
  crate and LLBC names, selector-safe start/opaque/include inventories,
  optional Aeneas subdirectory, and exact output map. The adapter derives every
  command from those fields; it contains no project identities or cardinality.
  The Cargo manifest is the package manifest itself and its literal
  `[package].name` must match. Start symbols are unique across invocations and
  may be supported local functions or types, both checked against the typed
  translation-report inventory.
- Every produced path maps one-to-one to a repository destination with an
  explicit `lean-source` or `translation-report` kind. Produced paths are exact
  inventory, not suffix searches. Mapping rows are tuple-sorted; paths are
  unique, prefix-disjoint, safe, and bounded; destinations are globally unique
  and strictly inside the generator-owned directory. Portable printable-ASCII
  paths make the 4096-character schema limit equal the runtime UTF-8-byte
  limit, and project-control components excluded from sealed shadows are never
  valid translation paths. Template-axiom and typed warning entries must name
  declared Lean destinations.
- Produced paths are relative to the Aeneas destination root. If an invocation
  selects `aeneas_subdir`, Lean outputs include and remain strictly beneath that
  prefix, while Aeneas's report is exactly root-level `translation.json`.
- Two runs compare normalized pretty-printed LLBC and raw mapped generated
  bytes. Normalization never changes the committed Lean or report bytes.
- `external-source-root` resolves each byte-pinned bridge module from exactly
  one declared repository source root, and module identities are unique. It
  does not become an invented Aeneas selector flag. `audited-rewrite` is
  reserved but rejected until its rewrite language, digest domain,
  implementation, and adversarial tests exist.
- `generated_dir` is the recursive deletion and atomic-replacement boundary;
  mapped destinations are the exclusive creation/modification allowlist inside
  it. Check rejects stale files. Update may delete stale entries only inside
  the validated non-symlink boundary and installs exactly the mapped tree.
  The orchestrator gives adapters only a sealed shadow, never a committed
  project path, and successful update work is not evidence.
- Translation evidence must name the registered v2 manifest and exactly match
  its ordered starts, claims, and budget, with empty committed-output and
  secondary-inventory lists. Cache identity includes the translation manifest,
  complete generated tree, handwritten refinement, bridge bytes, and positive
  and negative bridge-module candidates automatically.

Inventory ceilings are part of the wire contract rather than private adapter
constants: 4096 invocations, claims, and symbols per selector list; 1024 source
roots, bridges, and template-axiom entries; 4096 warning entries; and 100,000
mapped outputs subject to the project's smaller `max_files`. Translation and
Cargo manifests obey `max_manifest_bytes`; generated and bridge files are
bounded by the declared/project byte budgets without a hidden smaller per-file
limit.

Version 1 is rejected rather than heuristically upgraded. A migration must
split each old global package list into explicit invocations and establish its
output inventory using the pinned tools in a disposable directory. The
checked-in demo and template maps use the pinned pilot's three-file shape as an
honest inactive illustration; they are not claimed observations of those
crates and must be replaced by each crate's dry-run inventory before evidence
activation.

## Consequences

Adding or changing a translation is now a manifest change rather than an
orchestrator-code change. Zero exit status cannot conceal a changed package,
symbol, LLBC name, output count, or destination. Extra translator output and
undeclared template files fail closed, and reviewed generated bytes remain
auditable without normalization.

The format is more verbose, and an initial pinned dry run is required to learn
the exact output inventory before registration. Existing version-1 manifests
do not load. Audited import rewriting remains unavailable instead of being a
configuration switch with no executable trust boundary.
