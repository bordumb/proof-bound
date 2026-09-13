# ADR 0023: Claim/evidence bounded-domain consistency

- **Status:** Proposed
- **Date:** 2026-09-11
- **Decision owners:** Proofbound maintainers
- **Origin:** Proofbound Runtime PBF-0007

## Context

A claim and its bounded or exhaustive evidence can currently duplicate the
same finite-domain registration while disagreeing about its identifier,
description, cardinality, or ordering key. Status derivation can then admit the
evidence while publishing the claim's stale description. Repeating that
derivation in the independent verifier does not repair the missing comparison.

## Proposed decision

When bounded evidence determines `BOUNDED_CHECKED`, or an exhaustive check is
explicitly admitted as finite proof, the compiled claim carries the exact
claim-owned bounded-domain identity. That identity contains the registered
identifier, description, cardinality, and a digest of the complete canonical
manifest domain, including its ordering key.

The compiler/status engine compares the claim registration only with the
primary evidence family that earns the standing. Every valid `bounded-check`
record must match when the standing is `BOUNDED_CHECKED`. Every valid
`exhaustive-check` record must match when policy admits exhaustive evidence as
finite proof. A cited domain-bearing record from the other family is
corroborating evidence and does not set the published domain.

The public finite-domain language must be the description from that same
claim-owned registration. In version 7, `registered_domain_language` is a
compatibility projection derived solely from `bounded_domain.description`; it
is not an independently authored claim input. The independent verifier
requires exact equality and repeats the primary-family domain checks from the
release payload rather than trusting the reported status. A future major wire
version may remove the projection.

A mismatch is a typed invalid-evidence diagnostic associated with the claim
and, on the producer side, the exact evidence unit. The expected and observed
domain identities remain visible in the structured diagnostic.

## Compatibility

The claim field is optional on the wire so historical receipts still parse.
Compiled-release versions 4 through 6 keep their historical verification
rules. A version-7 receipt that claims bounded standing or policy-admitted
finite proof without the exact field is invalid. Existing bounded projects
must align the claim and the applicable primary evidence family before
updating.

This decision does not establish representativeness outside the finite domain
or the truth of a failed or unverified model-check receipt.

## Required falsifiers

- missing claim domain;
- mismatched identifier, description, cardinality, or canonical registration
  digest (including ordering-key drift);
- substitution of a primary passing receipt from another finite domain;
- unrelated domain-bearing corroborating evidence, which must remain valid;
- a mismatched exhaustive receipt when policy admits exhaustive evidence as
  finite proof; and
- mutation of the claim domain or public domain language in a compiled release.

Producer and independent-verifier conformance tests must reject each case.

## Review gate

The implementation is present on the PBF-0007 claim-wave branch. This ADR
remains proposed until a reviewer other than the change author approves both
the contract and the producer/verifier tests.
