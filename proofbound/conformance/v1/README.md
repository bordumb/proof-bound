# Proofbound v1 conformance corpus

This directory is the registered, language-neutral conformance corpus for the
status rules in specification sections 6.3, 10.4, and 19. Implementations must
parse the raw cases and map them into their own domain model independently;
the file is deliberately not a serialization of any Rust type.

## Status cases

`status-graphs.json` has schema `proofbound-status-conformance/1`. Each case is
a one-claim synthetic assurance graph expressed with symbolic IDs. Its
`expected` object is the exact derived facet tuple:

- `formal`: `PROVED`, `BOUNDED_CHECKED`, `TESTED`, `OPEN`, or `INVALID`;
- `linkage`: `REFINED`, `ARTIFACT_BOUND`, `TRANSCRIBED`, `MODEL_ONLY`, or
  `null` when invalid;
- `assumption`: `NONE` or `ASSUMED`, plus the exact sorted assumption and
  undischarged-premise ID sets;
- `policy_admitted`: the exact release-policy decision.

Evidence entries are cited and present by default, have outcome `passed` by
default, and use symbolic `theorem_ref` and `premises` references. The optional
theorem field `typed_binding` defaults to `true`; `false` requires an unrelated
plain theorem statement so implementations can prove that artifact-checker
output cannot manufacture `ARTIFACT_BOUND`. The optional
`asserted` object represents an adversarial producer-reported status which an
independent verifier must reject even though `expected` remains the correct
derivation.

Case-level `tier` is the project tier. Optional `claim_tier` is the claim's
lower ceiling; when absent it inherits the project tier. A policy profile and
an evidence kind keep their own minimum tiers even when combined—for example,
`ledger` may admit an independent check as empirical support, while the
independent-check record itself still requires Tier 1.

The corpus covers every formal and linkage facet, evidence precedence,
explicit exhaustive-check admission, the Tier 0 `ledger` cap, assumptions and
premises, primary-linkage selection, tier and policy blocks, failed/drifted/
missing/unregistered evidence, and omission or status-upgrade attacks.
It includes the security regression where passing artifact evidence cites an
admitted but unrelated theorem and must derive `INVALID`, never
`ARTIFACT_BOUND`.

## Canonical release fixture

`release-valid/` is a fully materialized, canonical
`proofbound-compiled-release/2-binding-preview` directory. CI must verify these committed bytes
in place; it must not generate or update the fixture first.

From the repository root:

```console
cargo run --locked -p proofbound-verify -- --release proofbound/conformance/v1/release-valid
```

The expected exit status is zero and the verdict is `receipt-consistent` with
publication policy `ADMITTED`.
