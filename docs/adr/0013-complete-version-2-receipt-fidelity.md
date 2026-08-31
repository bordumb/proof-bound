# ADR 0013: Complete version-2 receipt fidelity

Status: accepted

## Context

Experiment 0004 exposed four losses in the original receipt wire. A registered
model-check unit's assumptions did not survive into bounded evidence. A
portable adapter that could not measure process-tree peak memory emitted zero,
making “not measured” indistinguishable from a measured zero-byte peak. An
optional reader-facing `public_language` replaced the internal claim
`statement` in the compiled release. Finally, an adapter could observe several
exact subprocesses while core provenance retained only one representative
command and discarded the aligned run records and normalization identifier.
The compiler also synthesized review evidence by inventing a process-shaped
command and run for a derivation that never launched that process. Without an
explicit execution kind, a complete process history and an internal derivation
could not be distinguished honestly.

ADR 0011 deliberately deferred these changes because adding fields or changing
their meanings under the version-1 schema would silently reinterpret existing
receipts. ADR 0012 introduced explicitly named `2-binding-preview` identities
so its independently verifiable artifact-binding change could stand alone
without assigning an incomplete meaning to `/2`. This change replaces those
preview identities with the coordinated `proofbound-evidence/2`,
`proofbound-compiled-release/2`, and `proofbound-release-envelope/2` wire. That
transition is the honest boundary at which to close the four remaining
fidelity gaps.

## Decision

### Registered bounded assumptions

`bounded_check.assumptions` is required, including when it is empty. The
assurance compiler copies the registered model-check unit's assumption strings
exactly and in their registered order, rejects blank strings and duplicate
exact strings, and compares cached or adapter-derived evidence with that
registration. It does not trim, classify, or translate these strings into
project-assumption ledger IDs.

The portable release records this exact projected list. It does not embed the
complete model-check manifest, so the standalone verifier validates that the
list is present, nonblank, and unique but does not claim an external
registration comparison it cannot perform.

### Nullable measured memory

`resource_usage.peak_memory_bytes` and the corresponding portable
`actual_cost.memory_bytes` field are required nullable values. A nonnegative
integer is a measurement; numeric zero therefore means a measured zero-byte
peak. JSON `null` means the process-tree peak was not measured. The declared
memory budget remains a required nonnegative integer and cannot fill in for an
unknown observation.

### Three distinct claim-language fields

The compiled claim retains its required internal `statement` unchanged and
retains optional `public_language` separately. Reported claim status carries a
required, derived `public_statement`. Its base is `public_language` when one
was registered and otherwise `statement`; bounded status appends the exact
finite-domain suffix required by Specification 0001 §6.3.2.

The producer and standalone verifier derive `public_statement` from the two
retained claim inputs. A display field cannot replace the registered internal
property, and drift in the rendered status is rejected.

The private compiler snapshot advances to `proofbound-compiled-project/2`,
and its claim-input identities use the `proofbound-claim-input/2` domain.
Reporting or release from a version-1 snapshot is rejected and requires a
fresh check. This prevents a legacy evidence-free ledger snapshot from
surviving the public/internal-language transition merely because its old
stored status still recomputes internally.

### Complete ordered execution provenance

Version-2 evidence provenance requires `execution_kind`. For
`observed-processes`, it replaces singular representative `command` with the
complete nonempty ordered `commands` array and an equally sized nonempty
ordered `runs` array. Run `i` has `command_index = i` and records a required
nullable exit status, raw stdout and stderr identities, normalized-output
identity, truncation state, and duration. No observed command or run may be
collapsed or omitted.

`compiler-internal` identifies evidence derived without launching a
subprocess. Its `commands` and `runs` arrays are both empty. The compiler must
not invent process provenance for such a derivation. Both execution kinds
retain a required nonblank `normalization` identifier and separately typed
`reproduction_command`, along with timing, configuration, budget, and usage
facts.

The generic adapter observation always describes observed processes and already
exposes the ordered command/run data; the compiler now preserves it rather
than selecting entries and discarding the rest. These fields record what the
implementation knows without assigning additional semantic roles to
individual commands.

## Rejected alternatives

- Reinterpreting version-1 fields was rejected because old and new evidence
  would share a schema name while asserting different facts.
- Encoding unknown memory as zero or copying the budget was rejected because
  both fabricate a measurement.
- Storing only rendered public text was rejected because a release reviewer
  could not audit the registered internal proposition.
- Hashing the full command sequence but omitting its structure was rejected
  because reviewers and the independent verifier could not inspect which run
  produced each result.

## Consequences

The four EXP-0004 receipt defects D03 through D06 are implemented in version
0.7 rather than remaining deferred limitations. Version-2 receipts are larger
and incompatible with version 1 by design. Portable review can distinguish
registered model assumptions, measured and unmeasured memory, internal and
reader-facing claim language, and every observed subprocess without
fabricating process history for internal derivations. Cross-field facts that
JSON Schema cannot express remain fail-closed semantic checks in the producer
and, when both sides are portable, the independent verifier.
