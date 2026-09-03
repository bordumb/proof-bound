# Frozen Assurance IR `/2` research contract

This document defines Experiment 0015's finite research candidate. It is not a
production Proofbound wire and does not revise the failed `/1` draft in place.

## Profile expansion

For profile `P` and six-digit suffix `N`, both implementations construct one
programme with ID `programme:<P.id>:<N>` and claim ID
`claim:<P.id>:<N>`. Identifiers for other records use their type, profile ID,
role or capability, and suffix. Raw identities are lowercase
`sha256:<64 lowercase hex>` values computed over the UTF-8 logical identifier;
domain-separated identities hash `domain || NUL || canonical-json(value)`.

Every programme contains one claim, one specification, one evidence record,
one uncertainty, every dependency/effect/artifact listed by the profile, one
expected invalidation record, a four-step derivation, and one expected
decision. Arrays are strictly lexical by their stable identifier except the
four derivation steps, which are in dependency order.

The specification contains exactly the five model roles, six required
mutants, six killed mutants, and separately derived suite and adequacy
identities. Every dependency is declared and observed. The evidence references
the exact complete dependency, effect, and artifact ID sets and the exact
specification ID.

An externally enforced effect references the profile's external-contract
dependency. Mediated and statically denied effects have no enforcement
reference. Opaque effects have no enforcement reference and make the programme
cache-ineligible. Every effect has an `observed` or `unused` disposition;
statically denied effects must be unused, while other registered effects are
observed.

A bound artifact corresponds to the generated artifact. A reproduced artifact
corresponds to the source artifact and has the same byte identity and size.
Other roles have no correspondence reference. The family must carry exactly
its registered artifact-role set.

The uncertainty kind has the exact model consequence. `marks-assumed` yields
the `assumed` assumption facet and is consumed by the decision.
`blocks-admission` is consumed and makes admission false. `informational` is
not consumed and changes neither admission nor the assumption facet.

Family formal and linkage facets come only from the model table. The four
derivation steps are `evidence-valid`, `family-facet`,
`uncertainty-evaluated`, and `admission-decided`; each consumes the exact prior
record or step IDs defined by its rule. The declared root is the admission
step. The derivation identity hashes the steps and root. The expected decision
must equal the derived decision exactly.

The invalidation scenario changes the first lexical dependency. Its exact
invalidated evidence set contains the sole evidence record, and its identity
hashes both fields. This retained output tests consistency between dependency
projection and invalidation rather than trusting an ambient cache key.

## Differential generation

Valid case `i` expands profile `i mod 6` with suffix `i`. Adversarial case `i`
expands the template registered by attack `i mod 28`, uses suffix `500000+i`,
and applies exactly that one mutation. `noncanonical-bytes` changes encoding
only; every other mutation changes one typed field or collection operation.

The model, templates, attacks, and generation records are opened before
execution. `expected.json` may be opened only by the post-implementation
evaluator after both kernels have produced complete reports.

## Error precedence

Validation proceeds in this order: strict decoding and canonical bytes;
schema and identifier shape; array order, uniqueness, and global aliases;
references and dependency completeness; effects; specification; artifact
roles and correspondence; uncertainty; family facets; invalidation;
derivation; expected decision. Each registered mutation is constructed so its
expected error is the first failure under this order.

## Bounded claim

Agreement covers only the six profiles, 28 attacks, and deterministic 500/500
generated corpus. It does not prove completeness of future evidence families,
soundness of actual effect enforcement, or correctness of either checker.
