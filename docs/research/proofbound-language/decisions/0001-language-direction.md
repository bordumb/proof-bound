# Research decision 0001: framework bridge first; assurance language incrementally

- **Status:** accepted research direction
- **Date:** 2026-09-04
- **Authority:** non-normative; not a production ADR
- **Inputs:** [cross-platform synthesis](../syntheses/cross-platform-enforcement.md),
  [Assurance IR `/2`](../assurance-ir-v2.md),
  [native prototype](../workstreams/native-runtime.md), and
  [foreign-boundary result](../workstreams/foreign-boundaries.md)

## Decision

Continue Proofbound as a framework and adoption bridge while developing the
Proofbound assurance language as an incremental, typed semantic layer. Do not
begin a from-scratch general-purpose programming language or position the
research bytecode as a production runtime.

The near-term product has three first-class surfaces:

1. existing Python, TypeScript, Rust, and other project adapters;
2. one backend-neutral Assurance IR and independent verification kernel; and
3. a typed assurance authoring language that compiles to that IR and can host
   small native assurance components where they materially strengthen claims.

Existing-language code is not temporary scaffolding. It is the migration path,
the interoperability boundary, and likely a permanent part of real systems.

## Why

The research supports a language-shaped semantic core. Independent
implementations agree on Assurance IR `/2`, the native prototype has exact
parsing and deterministic bounded execution, and mixed Python/TypeScript graphs
preserve proof, test, assumption, compiler, runtime, and bridge distinctions.
Cross-platform experiments show that a shared effect policy can compile to
real macOS, Linux, and Windows boundaries without flattening their evidence.

The research does not support replacing the ecosystem. The native artifact is
research bytecode rather than verified machine code; frontend diagnostics are
not confirmatory; arbitrary FFI remains open; Windows network attribution is
weaker than macOS and Linux; and the deferred human study has not shown that a
new syntax improves decisions or reduces fatigue. A new general-purpose
language would add compiler, debugger, package, editor, deployment, and hiring
cost before those product questions are answered.

## Product shape

```text
existing repositories            Proofbound assurance source
Python / TypeScript / Rust        claims / effects / uncertainty
          \                         /
           adapters + source provenance
                       |
                 Assurance IR
                       |
          small independent verifier
                       |
       platform capability + evidence profile
                       |
        claim graph, reuse, and notifications
```

Native Proofbound code may grow inside this architecture, but it earns scope
one assurance-critical component at a time. The bridge remains usable even if
the native language never becomes a general-purpose runtime.

## Rejected directions

- **New general-purpose language now:** rejected because the ecosystem and
  artifact-correctness costs are not justified by current bounded evidence.
- **Framework only, no language:** rejected because typed effects, evidence
  states, claim consequences, and invalidation rules already form a coherent
  language-level semantic core.
- **One backend-neutral denial boolean:** rejected by the Windows result; it
  would either overclaim Windows evidence or discard stronger macOS/Linux
  evidence.
- **Backend-specific assurance languages:** rejected because the common IR and
  independent-kernel results already demonstrate a compact shared core.

## Near-term execution plan

1. Stabilize the Assurance IR around typed outcomes, platform capabilities,
   explicit assumptions, and claim-local reuse.
2. Repeat the frontend study with valid controls and source-aware diagnostics.
3. Productize the framework bridge across representative repositories and make
   unsupported platform evidence visible rather than fatal to unrelated claims.
4. Expand native code only for assurance-critical components where it creates
   stronger independently checkable evidence than an existing-language bridge.
5. Run the deferred notification-fatigue study before making product claims
   about comprehension, response time, or interruption reduction.

## Review triggers

Reconsider a full native language only when all of the following are true:

- source-aware authoring and diagnostics pass a confirmatory study;
- native source-to-artifact evidence materially exceeds a comparable verified
  Rust or existing-language integration;
- representative mixed-language migrations are usable and keep the bridge
  first-class;
- platform capability profiles behave predictably on production-like hosts;
- the independent kernel remains small as coverage grows; and
- human evidence shows that the assurance model improves decisions without
  increasing missed critical consequences.

Until then, “Proofbound language” means a typed assurance language over the
framework—not a replacement programming ecosystem.
