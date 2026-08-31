# ADR 0011: Preserve bounded facts and make artifact binding verifiable

Status: accepted

## Context

Experiment 0004 applied Proofbound to the crates.io `base64` 0.22.1 package.
Its bounded pilot registered a finite domain, CaDiCaL, unwind 6, and four exact
Kani harnesses. The adapter ran that registration, but the compiled `/1`
evidence replaced the solver with `registered-kani-backend` and emitted an
empty unwind map. Reader output then replaced the checked property with the
finite-domain description. The first receipt therefore lost both execution
semantics and claim meaning even though the underlying Kani runs passed.

The same run exposed four facts that do not fit the existing `/1` wire shape:
model-check assumptions have no evidence field; an unobserved peak-memory
value becomes zero; optional reader-facing `public_language` substitutes for
the internal claim statement; and an adapter's sequence of exact subprocess
commands collapses to one representative provenance command. Changing the
meaning of existing fields would make old and new `/1` receipts
indistinguishable, so these defects cannot be repaired by an undocumented
reinterpretation.

The Pattern A pilot exposed a separate, security-relevant boundary. Its first
configuration associated artifact evidence with a theorem about corpus
meaning that did not mention the artifact digest. A different digest theorem
was present but exempt from the claim. Because the canonical-artifact checker
supplied six successful binding booleans, Proofbound nevertheless rendered
the claim `ARTIFACT_BOUND`. The receipt established that a checker said the
relationships held; it did not establish that the audited theorem itself
bound those exact bytes.

The first post-fix Q2 release exposed a producer/verifier canonicalization
split already seen in Experiment 0001: producer canonical JSON retained an
empty `provenance.additional_closures` array, while the standalone verifier's
typed canonical form omitted the empty optional collection. The verifier
correctly rejected the byte mismatch as `PBV_NON_CANONICAL`; that release is
not portable evidence.

Review also corrected the case description. The B64F envelope and assembled
fixture corpus were produced by the experiment. Some literal vectors came
from the pinned subject, other positive cases were derived transformations,
and negative cases were adversarial mutations. The independent Lean decoder
shared no implementation code with the subject, but the artifact was not an
uncontrolled foreign fixture.

## Decision

### Bounded facts that fit the existing shape

Proofbound 0.6 projects bounded execution semantics from the exact registered
model-check unit:

- the receipt solver equals the registered nonempty solver;
- the receipt harness set and unwind-map key set are identical to the exact
  registered harness inventory;
- every harness receives the registered nonzero unwind bound; and
- core and the independent verifier reject empty, missing, extra, or zero
  per-harness unwind entries.

The producer compares the registered model-check unit with the evidence-unit
registration, projects the exact solver and unwind value, and rejects a
different cached record. The independent release verifier has no source model
unit in the `/1` release payload: it independently validates a nonempty solver,
exact harness/unwind key coverage, and nonzero values, but does not compare the
solver or unwind value with an external registration.

Reader output preserves both halves of a bounded claim. It renders the
compiled reader-facing property, the literal separator ` Registered finite
domain: `, and the registered domain description. The independent verifier
validates that bounded standing has nonempty registered domain language; the
current release format contains no serialized status display for it to compare.

This is a revocation, not grandfathering. An older bounded `/1` receipt with
empty, partial, extra, mismatched-key, or zero unwind coverage is no longer
admitted under Proofbound 0.6, even if it was previously accepted. A cached
receipt whose solver or unwind value differs from the registered model unit is
rejected by the producer and cannot be reused for a registered Kani unit.

### Facts that require a new wire version

Do not silently redefine `proofbound-evidence/1`,
`proofbound-compiled-release/1`, or their schemas. A versioned receipt
migration must represent, at minimum:

- registered model assumptions and their disposition;
- resource observations that distinguish an unknown value from measured
  zero;
- separate internal and reader-facing claim statements, each with an
  auditable identity; and
- the ordered exact subprocess sequence when one evidence unit executes more
  than one command.

Until that migration lands, experiment records must name these losses and
must not infer that the current receipt contains the omitted facts.

### Cross-implementation canonical empty collections

The producer and verifier must serialize optional empty collections
identically before hashing. This is an implementation bug within the current
wire shape, not permission to weaken the verifier or accept two canonical
encodings. Normalize the producer representation to the schema's typed
canonical form, add a cross-implementation regression, and require a fresh
standalone-verifier pass before calling the Q2 release portable.

### Artifact binding

The corrected experiment case uses one exact declaration,
`Base64Fixture.Claims.publishedArtifactSoundness`, for the theorem evidence,
artifact binding, and claim attribution. Its theorem type conjoins the
fourteen-case corpus meaning with the equality between the kernel-computed
SHA-256 of the published bytes and the registered digest. That case is useful
positive evidence for the intended Pattern A mechanism.

It is not a framework fix. The current canonical-artifact admission path still
cannot establish from independently checkable structure that its associated
theorem entails the claimed digest relationship; it can accept
checker-authored booleans. A future protocol must make the binding theorem a
typed, kernel-audited object tied to the exact theorem declaration, statement
identity, artifact digest, and attributed claim. The independent verifier must
validate those links rather than trusting an adapter's summary flags. Until
that redesign lands, a successful canonical-artifact check is not by itself
evidence that the theorem mentions or proves the digest.

Finally, describe provenance literally. Experiment 0004 demonstrates Pattern
A over an experiment-owned canonical envelope containing subject-derived and
adversarial vectors. It does not answer the pre-registered foreign-fixture
question in the affirmative.

## Consequences

The bounded result can state its exact property, finite domain, solver, harness
inventory, and unwind bounds without changing the `/1` object shape. The
stricter validation deliberately invalidates underspecified older bounded
receipts.

The remaining receipt losses stay visible and require an explicit version
transition. The corrected base64 theorem remains a strong mechanism result,
but the artifact-binding admission hole remains open and Experiment 0004 Q3
fails because its artifact was experiment-owned.

The initial Q2 status result satisfies that question's registered criterion.
Its first 0.6 release was noncanonical and remains rejected evidence. After
normalizing the empty collection and adding producer/verifier regressions, a
fresh release passed the bundled standalone verifier as `receipt-consistent`;
its payload is
`sha256:03e6e481ed1c169d2103a9f72e81bae496c63f1cb7caa8552e8e8e52129084d1`.
