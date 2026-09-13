# Proofbound as a cross-domain assurance platform

[Documentation map](../README.md) · [Working notes](README.md)

- **Status:** exploring
- **Created:** 2026-09-04
- **Last updated:** 2026-09-04
- **Purpose:** Record how Proofbound could evolve from a build-time assurance
  compiler into a reusable substrate for high-consequence products, beginning
  with a separate agent-execution gateway called Kernel of Proof.

## Summary

Proofbound's present implementation should not be mistaken for its architectural
ceiling. The enforced-effects research suggests a larger product direction: a
small assurance kernel that composes claims, proofs, bounded checks, platform
enforcement, artifact identities, deployment measurements, execution receipts,
and accountable human reviews without letting any result borrow a stronger
meaning than it earned.

The target is not a universal prover. Proofbound should remain domain-neutral
and should not absorb agent sandboxes, trading rules, medical semantics,
cryptographic algorithms, or hardware models. Those belong in external products
and typed plugins. Proofbound's role is to define a small, closed set of evidence
meanings; validate exact identities and legal relationships; derive faceted
status; and emit receipts that another implementation can verify.

The first external product should be **Kernel of Proof (KOP)**: a Linux-first
agent-execution assurance gateway in its own repository. KOP would enforce a
declared authority boundary and produce per-run execution receipts. Proofbound
would be used to develop and release KOP, and would compile the evidence that
justifies claims about each KOP version. KOP should force the next reusable
Proofbound capabilities: execution and deployment subjects, recursive receipts,
typed enforced-effect evidence, verified policy compilation, and artifact-to-
deployment binding.

## Why the opportunity is larger than the current implementation

Proofbound currently concentrates on claims about source, evidence units, and
release artifacts. Several experiments show that the same discipline can extend
to an effectful execution boundary:

- [Experiment 0018](../experiments/0018-os-enforced-effects/CONCLUSION.md)
  exercised one typed policy and receipt model across Python, Node, and Rust on
  an identified macOS Seatbelt boundary. Its assurance questions passed, while
  its frozen wall-time criterion failed; the registered result was `revise`.
- [Experiment 0019](../experiments/0019-batched-enforcement-latency/CONCLUSION.md)
  preserved independent per-process boundaries while reducing the same 51-run
  corpus from 93,574 ms to 6,048 ms. It passed its preregistered criteria but did
  not authorize production reuse.
- [Experiment 0024](../experiments/0024-linux-loader-closure/CONCLUSION.md)
  passed on a native Ubuntu ARM64 runner after adding the exact ELF interpreter
  to the registered execution closure. Its result remains bounded to that
  platform, mechanism, runtime closure, and attack corpus.
- [Experiment 0025](../experiments/0025-windows-initialization-closure/README.md)
  has a frozen Windows initialization candidate but has not yet executed its
  confirmation. Windows equivalence therefore remains open.

These results do not prove that arbitrary agent executions are hermetic. They do
show that exact authority plans, OS policies, runtime identities, raw outcomes,
denial evidence, invalidation, and independent validation can share one typed
contract without accepting a child-authored `sandboxed = true` assertion.

The research supports a product hypothesis:

> Proofbound can extend from assurance about what was built to assurance about
> what was deployed and what authority a particular execution received.

## The common assurance chain

Each proposed vertical needs a version of the same chain:

| Stage | Required question |
| --- | --- |
| Intended property | What must remain true, and what remains outside the claim? |
| Formal property | Which exact machine-checked proposition represents the claim? |
| Implementation | Which source closure implements the relevant behavior? |
| Artifact | Which binary, circuit, firmware image, or certificate was produced? |
| Deployment | Which exact artifact and configuration are running? |
| Execution | Which inputs, authority, platform, and boundary governed this run? |
| Consumer | Can another party validate the chain without trusting its producer? |

Proofbound already models substantial parts of the first four stages. The next
architectural step is to extend the graph across deployment and execution while
preserving the existing evidence distinctions.

### Recursive assurance receipts

A verified receipt should be eligible to become typed evidence in a larger
claim closure. This creates composition without requiring one producer to share
its repository with every consumer.

For KOP:

1. A Proofbound release receipt establishes the admitted properties of one KOP
   release.
2. A deployment receipt binds the released binary and policy compiler to a
   platform measurement or installation identity.
3. A KOP execution receipt binds one agent run to that deployment, its exact
   policy, inputs, runtime, outputs, and raw outcome.
4. A downstream verifier checks the composed chain and retains every premise
   inherited from the release, deployment, and execution boundaries.

Receipt composition must be typed. A valid execution receipt cannot upgrade a
`TESTED` release to `PROVED`, remove a kernel assumption, convert an observed
effect into an enforced one, or turn an artifact digest into a behavioral
theorem.

## Proofbound capabilities to explore

### 1. Execution and deployment subjects

The graph needs subject kinds for at least:

- a released artifact;
- a deployment or measured instance;
- an execution plan;
- one execution attempt; and
- outputs produced by that attempt.

Release, deployment, and execution are different semantic events. Their
receipts need separate schemas, identities, freshness rules, invalidation
conditions, and report language.

### 2. First-class enforced-effect evidence

The experimental contract could become an external
`proofbound-enforced-effects` plugin with typed records for:

- platform-neutral authority plans;
- allowed filesystem, environment, process, network, and write effects;
- policy compilation and exact policy bytes;
- enforcement mechanism, platform, runtime, and loader identities;
- installation of the boundary before user code executes;
- fresh execution and output roots;
- raw process outcomes and bounded streams;
- reviewed-tree preservation;
- positive and denial probes;
- denial non-reuse;
- cache and freshness decisions; and
- platform assumptions and unsupported authority classes.

The plugin must not author its own status. It produces a typed observation;
Proofbound core and the independent verifier derive its consequences. An
unsupported mechanism emits no reusable enforcement evidence.

### 3. Verified policy compilation

The strongest reusable KOP theorem is not “Linux is secure.” It is a refinement
claim about policy compilation:

> Compiling an abstract authority policy into the supported platform policy
> never grants an effect outside the abstract policy.

The corresponding evidence path requires:

- formal semantics for the platform-neutral policy;
- formal semantics for the supported Landlock and seccomp subset;
- a proved or independently checked compiler relation;
- exact binding to the emitted policy bytes;
- a launcher sequencing argument; and
- explicit premises covering Linux, the selected LSM and syscall mediation,
  loader behavior, and the registered platform surface.

The policy compiler and receipt rules should live in a safe, deterministic Rust
kernel suitable for Kani and Charon/Aeneas. The effectful Linux launcher should
remain a separate, minimal boundary. Evidence about the launcher must not be
presented as source refinement merely because its pure input validator is
proved.

### 4. Artifact and deployment lineage

Artifact binding should be able to represent an ordered chain such as:

| From | Transformation or relation | To |
| --- | --- | --- |
| Reviewed source closure | Compiler invocation | Intermediate or binary artifact |
| Binary | Image builder | Container or enclave image |
| Image | Signing operation | Signed release identity |
| Signed image | Platform measurement | Deployed instance |
| Deployed instance | Execution plan | One runtime attempt |

Every step needs exact inputs, outputs, tools, algorithms, and premises. Digest
algorithms should use a closed, versioned vocabulary rather than an arbitrary
string. SHA-256 remains appropriate for current artifact bindings, while
platforms such as AWS Nitro use SHA-384 PCR measurements and therefore require
a distinct typed binding.

A digest proves identity, not behavior. A chain becomes behavioral only when it
also contains the required source refinement, translation validation,
reproducible-build, verified-compiler, or machine-semantics evidence.

### 5. Additional evidence families

The proposed verticals require non-interchangeable evidence about:

- temporal properties and state-machine transitions;
- concurrency and linearizability;
- information flow;
- constant-time execution and other side channels;
- resource and real-time bounds;
- fault response and zeroization;
- circuit constraint coverage;
- hardware and firmware measurements; and
- operational or regulatory review.

These should be implemented as typed plugins whose status effects are fixed by
versioned Proofbound policy. A constant-time result cannot award functional
correctness. A model theorem cannot establish a real-time deadline. A hardware
measurement cannot establish the measured artifact's semantics.

### 6. Accountable formalization review

Natural-language intent cannot be mechanically equated with a Lean proposition.
Proofbound can make the remaining human boundary attributable and invalidated on
change. A formalization review record could bind:

- reviewer identity and role;
- exact internal and reader-facing language;
- exact elaborated formal proposition;
- source revision and semantic closure;
- review scope and exclusions;
- independence requirements;
- approval, expiry, and supersession; and
- a signature over the complete record.

The review does not turn prose into a theorem. It records who accepted the
mapping and ensures that changing either side requires another review.

### 7. Signed, multi-party assurance

Content identities provide integrity but not organizational accountability.
Auths could supply deliberately trusted signer identities and bounded delegated
authority for:

- claim authors;
- formalization reviewers;
- evidence producers;
- release approvers;
- platform operators; and
- downstream verifiers.

This suggests a coherent product relationship without coupling their cores:

| Project | Question answered |
| --- | --- |
| Auths | Who produced, reviewed, or authorized this record? |
| Proofbound | What does the registered evidence entitle the project to claim? |
| Kernel of Proof | What authority did this execution receive? |

Signatures must not upgrade evidence. They establish attribution and delegated
authority over an exact record, not the truth of the record's proposition.

### 8. A strict plugin boundary

Domain semantics must remain outside Proofbound core. A plugin may:

- own a versioned evidence schema;
- discover and run an exact tool inventory;
- produce canonical observations;
- identify its tool, configuration, inputs, outputs, and TCB; and
- request one of a closed set of core evidence meanings.

A plugin may not:

- define an arbitrary status label;
- supply a reusable success Boolean;
- reinterpret an existing evidence kind;
- omit unsupported or unobserved authority;
- hide a domain bound in adapter output; or
- make its implementation and independent validation share semantic code while
  claiming independence.

Generic mechanisms should first be implemented in the consuming product. They
should become a reusable Proofbound plugin only after a second unrelated
consumer demonstrates that the abstraction does not contain product semantics.

## Product verticals

### Kernel of Proof: agent execution assurance

KOP is the closest extension of demonstrated research. It should be a separate
Linux-first repository using Proofbound for its own development and releases.
Its product runtime enforces authority; Proofbound does not sit in the runtime
security path.

KOP could register claims such as:

- a child cannot read undeclared project files within the registered Landlock
  boundary;
- a child cannot contact the network through the registered syscall surface;
- writes are confined to a fresh ephemeral root;
- an unregistered executable cannot run;
- a denied or incomplete execution cannot emit a reusable receipt;
- every receipt binds the runtime, policy, inputs, outputs, platform, and
  enforcement mechanism;
- every security-relevant input change invalidates reuse; and
- an unrelated source change does not invalidate an unaffected execution.

The status language must retain the platform and mediation boundary. KOP should
not claim mathematical absence of exfiltration, arbitrary kernel exploits, or
side channels unless additional evidence actually closes those properties.

KOP needs two receipt families:

1. A **Proofbound release receipt** describing what has been established about
   one KOP release.
2. A **KOP execution receipt** describing the authority, boundary, identities,
   outcome, and outputs of one agent run.

The release receipt supports trust in the mechanism. The execution receipt is
evidence about a particular run. Neither substitutes for the other.

### Confidential-computing workload assurance

Proofbound could compose an enclave behavior theorem, a binary or image binding,
and a hardware attestation measurement. Required extensions include typed
attestation documents, closed measurement algorithms, image-component roles,
deployment subjects, and inherited platform premises.

The specialised product still owns kernel verification, information-flow
properties, compiler and firmware assumptions, hardware behavior, and side-
channel analysis. Remote attestation proves which measured image ran; it does
not prove that the image cannot leak plaintext.

### Trading and clearing kernels

Proofbound could support exact claims about order conservation, price-time
priority, pre-trade limits, clearing invariants, and deterministic replay. It
would need temporal and state-machine evidence, exact decimal arithmetic,
sequence-domain registration, concurrency evidence, performance measurements,
and operational review records.

The first credible product is a small deterministic pre-trade or clearing
kernel, not an immediate claim that an entire nanosecond matching system is
race-free. Exchange rules, effectful integration, latency behavior, operational
controls, and regulator acceptance remain specialised work.

### Medical-device evidence and control kernels

Proofbound could extend its graph with requirements, hazards, mitigations,
verification activities, validation evidence, change-control reviews, and
release approvals. This would produce stronger, drift-resistant traceability
than a document assembled after implementation.

It must not be described as “executable IEC 62304” or automatic approval.
Clinical evidence, quality systems, human factors, risk management, post-market
obligations, and regulator judgment remain outside a software assurance
receipt. The likely first product is an evidence and traceability compiler, not
a new implantable-device kernel.

### HSM authorization and key-lifecycle kernels

Proofbound is well suited to small claims about quorum authorization, key-state
transitions, rollback prevention, import and export policy, and zero reusable
authority after destruction. Required plugins would represent constant-time
analysis, information flow, zeroization, fault behavior, firmware images,
secure-boot measurements, and hardware TCB components.

An artifact-bound functional theorem does not establish physical tamper
resistance, side-channel freedom, correct hardware behavior, or FIPS/Common
Criteria certification. Those remain distinct evidence and review paths.

### ZK circuit and verifier release assurance

This is a strong fit for Proofbound's artifact-oriented pattern. A claim closure
could bind:

- circuit source and compiler identity;
- exact constraint inventory;
- witness and public-input mapping;
- proving and verification keys;
- host verifier behavior;
- on-chain verifier bytecode; and
- the state transition authorized by successful verification.

Proofbound would need typed circuit and key subjects, constraint-coverage
evidence, compiler translation checks, and host-to-chain artifact lineage. The
domain product still owns the proof that the circuit is sufficiently
constrained and that its mathematical statement matches the intended protocol.

### Post-quantum migration assurance

Proofbound could bind a migration to exact algorithm and parameter-set versions,
known-answer vectors, negative vectors, differential implementations,
configuration, protocol negotiation, binary artifacts, and constant-time or
side-channel evidence. This is more credible than beginning with a new complete
TLS implementation.

The specialised product still owns cryptographic security arguments, optimized
and assembly paths, microarchitectural leakage analysis, hardware acceleration,
interoperability, and validation under the applicable standards programme.

## KOP as the first forcing function

The recommended sequence is:

1. Create KOP in a separate repository.
2. Keep its platform-neutral policy semantics in a safe, deterministic Rust
   kernel and its Linux launcher in a separate effectful crate.
3. Register KOP's claims, assumptions, attack corpus, and platform boundaries in
   Proofbound before presenting production assurance.
4. Add execution and deployment subject prototypes to an external plugin rather
   than Proofbound core.
5. Promote the enforced-effects experiment contracts into versioned schemas and
   independent validators.
6. Prove authority attenuation, policy normalization, and receipt non-reuse in
   Lean; retain OS mediation as explicit premises.
7. Execute one complete `PROVED · REFINED` path for the pure KOP kernel.
8. Bind the proved release to exact product artifacts.
9. Compose a release receipt with a per-run execution receipt.
10. Add Auths signatures for operators, reviewers, and release authorities.
11. Exercise the same generic receipt-composition machinery in a second vertical,
    preferably ZK artifact assurance.
12. Only then decide which mechanisms are stable and domain-neutral enough to
    promote into Proofbound's normative specifications.

## Constraints that preserve Proofbound's thesis

This direction is valuable only if the following constraints remain intact:

- Proofbound composes evidence; it does not manufacture domain proofs.
- Tests never become theorems, and denial probes never become universal absence
  proofs.
- A digest establishes artifact identity, not behavior.
- Platform attestation establishes measured deployment identity, not semantic
  correctness.
- Performance measurements remain bounded observations unless supported by a
  separate proof.
- Human approval establishes accountable judgment, not mathematical truth.
- A valid downstream receipt inherits every upstream assumption and TCB
  component.
- Missing execution, platform, measurement, or linkage evidence can only weaken
  status.
- Product plugins cannot introduce new status meanings without a reviewed,
  versioned core contract and an independent verifier implementation.
- `proofbound check` remains verify-only; only explicit update operations may
  rewrite committed policy, generated artifacts, or registered evidence.

## Promotion criteria

This note should become a research programme when all of the following are
true:

- KOP has a separate repository with a frozen threat model and claim inventory;
- one Linux execution receipt composes with one Proofbound release receipt;
- core and independent verifier reject omission, substitution, downgrade,
  replay, and assumption-loss attacks across that composition;
- the pure KOP policy kernel has a real source-refinement receipt rather than a
  model-only theorem;
- one deployment identity is bound without presenting identity as behavior;
- Windows remains explicitly unsupported or completes its frozen confirmation;
  and
- a second non-agent vertical uses the same generic receipt-composition contract
  without importing KOP semantics.

Accepted graph meanings and wire behavior should then move into a Proofbound
specification. Trust-boundary decisions should move into ADRs. Until those
criteria are met, this document remains an exploration rather than a product
promise.
