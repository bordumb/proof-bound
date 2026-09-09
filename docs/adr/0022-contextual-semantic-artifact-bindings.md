# ADR 0022: Bind closed artifact sets inside reviewed release contexts

- **Status:** Accepted
- **Date:** 2026-09-08
- **Decision owners:** Proofbound maintainers
- **Related:** Specification 0001 sections 5, 6.3, and 9.4; ADR 0012;
  ADR 0020; ADR 0021; Runtime feedback PBF-0011

## Context

ADR 0012 makes `ARTIFACT_BOUND` derive from the exact elaborated root of an
admitted theorem rather than from a checker-authored Boolean. ADR 0020 adds an
orthogonal empirical relation for procedures that observe exact artifact
bytes, and ADR 0021 lets release-only observations live in reviewed activation
contexts.

The three decisions do not yet compose for theorem-derived release binding.
`Proofbound.Artifact.DigestBindingV1` names exactly one artifact, while reviewed
contexts admit only schema-version-5 exact observations. A project that ships
different bytes for several architectures therefore cannot keep source-only
checks portable and also connect one admitted semantic claim to each exact
native release artifact.

Binding a digest catalog is not equivalent: it establishes correspondence to
the catalog bytes, not the executable. Treating an observation as semantic
binding would promote empirical evidence. Generating unreviewed theorem or
manifest configuration after a build would move the claim, path, digest, or
meaning outside the reviewed tree.

The requirement is generic. Platform wheels, CPU-specific libraries, firmware
images, and compiler target binaries all need the same closed relation.

## Decision

Proofbound will support a versioned **closed digest-binding set** and
**contextual artifact-soundness** evidence. The theorem remains the only source
of semantic binding facts; a contextual artifact checker reports only the exact
identity of one selected member.

### Typed theorem root

Lean gains two domain-neutral types:

```lean
structure DigestBindingMemberV1 where
  artifactLogicalName : String
  expectedSha256 : String
  bytes : ByteArray

structure DigestBindingSetV1
    (claimId artifactSchema : String)
    (members : List DigestBindingMemberV1)
    (meaning : ByteArray → Prop) : Prop where
  digest : ∀ member ∈ members,
    "sha256:" ++ Proofbound.sha256Hex member.bytes = member.expectedSha256
  meaning_holds : ∀ member ∈ members, meaning member.bytes
```

The public theorem's exact outermost elaborated statement must be
`Proofbound.Artifact.DigestBindingSetV1 claimId artifactSchema members meaning`.
The claim ID and artifact schema are direct canonical string literals. `members`
must be a direct `List.nil`/`List.cons` spine of exact
`DigestBindingMemberV1.mk` applications. Every member's logical name and digest
must be direct canonical string literals. The bytes expression may name a
reviewed definition because large artifacts are not copied into manifests or
receipt metadata.

The member list is nonempty, bounded, strictly ordered by logical name, and has
unique logical names and digests. Digest values use canonical lowercase
`sha256:` spelling. The complete theorem statement and statement identity
remain in theorem evidence. The existing singular `DigestBindingV1` form is
unchanged.

The Lean adapter validates the complete set shape whenever the new marker
occurs. Core and the independent verifier parse it again without reduction.
Nested markers, wrappers, aliases, malformed constructors, computed metadata,
duplicate members, and unknown marker versions fail closed.

### Selected contextual member

Evidence-unit schema version 6 registers one contextual
`artifact-soundness` unit. It has all existing artifact-soundness qualifiers,
names one registered reviewed context, and points to one exact artifact input.
The canonical-artifact adapter recomputes the input's logical name, SHA-256,
and byte size. It cannot author a theorem identity, member set, or binding flag.

The compiler resolves the unit's named theorem from reviewed theorem evidence,
parses the theorem's exact binding set, and requires the checked artifact's
logical name and digest to match exactly one member. The resulting artifact
binding record retains the selected context and exact checked identity. An
inactive context establishes nothing.

A base check executes no contextual artifact-soundness units. A contextual
full-project check executes every base unit plus only the selected context's
units. Release construction requires every selected context unit to produce
the evidence detail registered for its schema: exact observations produce
observation detail and contextual artifact-soundness units produce binding
detail.

### Claim and status semantics

The closed-set theorem may also be the theorem named by source-refinement
evidence. Its `meaning` must contain the source-to-artifact proposition the
project intends to admit, including any compiler or build premise. Proofbound
does not synthesize that proposition from a build success or digest.

Context activation adds a valid `ARTIFACT_BOUND` linkage candidate only when
the exact theorem/member/artifact join succeeds. Existing primary-linkage rules
remain unchanged. A claim that selects `REFINED` may retain contextual artifact
binding in its detailed closure without changing its summary facet. Selecting
a context never creates `PROVED`, `REFINED`, or `ARTIFACT_BOUND` by itself.

Empirical exact-artifact observations remain orthogonal and cannot satisfy this
path. Tests, bounded checks, property tests, independent checks, and observation
records retain their existing ceilings.

### Portable release and independent verification

A contextual release containing artifact bindings uses a new compiled-release
and envelope schema. Every portable contextual binding record carries the same
release evidence context already used by observations. The independent
verifier:

1. validates the canonical release and context;
2. independently parses the admitted theorem statement and closed member set;
3. requires the selected checked artifact identity to match exactly one member;
4. recomputes the supplied or sealed artifact bytes, including byte size;
5. rejects inactive-context evidence and context substitution; and
6. independently re-derives the claim's formal, linkage, and assumption facets.

`record-consistent` may describe a structurally valid receipt whose external
artifact bytes were not supplied. Only recomputation of every external artifact
and procedure required by the selected release can yield `bytes-observed`.
Neither verdict changes evidence meaning.

### Fail-closed rules

Compilation or verification rejects:

- an empty, oversized, unsorted, or duplicate binding set;
- a malformed member constructor or nonliteral identity field;
- a marker nested below another proposition or occurring more than once;
- a contextual artifact unit outside evidence-unit schema version 6;
- a schema-version-6 unit that is not contextual artifact soundness;
- an unknown or untracked context manifest;
- a selected artifact absent from the theorem member set;
- logical-name, digest, size, theorem, claim, schema, or context substitution;
- omission or replay of a selected contextual binding;
- use of an exact observation as artifact soundness; and
- any formal or linkage upgrade not independently derivable from admitted
  theorem and binding evidence.

### Compatibility

Existing projects, `DigestBindingV1` theorems, unconditional
artifact-soundness units, schema-version-5 observations, and older release
schemas retain their current meaning. New tools accept both theorem forms but
emit the new portable schema only when contextual artifact binding is present.
Older tools reject evidence-unit schema version 6 and the new portable schema
rather than silently ignoring the relation.

## Implementation sequence

Each item is a separate reviewable commit.

1. Freeze this decision and its adversarial conformance inventory.
2. Add the Lean marker plus identical strict set parsers in the adapter, core,
   and independent verifier.
3. Add schema-version-6 contextual artifact-soundness registration and
   deterministic base/context selection.
4. Project the selected context through evidence, compiled releases, envelopes,
   and independent verification.
5. Execute the frozen producer/verifier attack inventory and update the
   normative specification and format documentation.
6. Adopt the capability in Proofbound Runtime without promoting empirical
   claims.

## Consequences

Projects can prove one reviewed semantic proposition over a closed family of
release artifacts and check one native member in each release context. The
release receipt identifies the exact executable bytes that were selected,
while source-only checks remain portable.

The cost is a new theorem form, evidence-unit schema, and portable release
schema. Large artifact bytes remain behind reviewed Lean definitions and
explicit proof assumptions where necessary; a digest or successful build never
becomes a semantic proof on its own.
