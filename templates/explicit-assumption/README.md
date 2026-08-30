# Explicit external-provider assumption template

This is a Tier-0 ledger pattern for a claim whose real-world interpretation
depends on an external system. Tests can show that software handles the
provider's Boolean response correctly; they cannot establish that the provider
identified a human correctly.

Copy the three manifests, replace every `EXAMPLE-*` identity and `path/to/*`
location, and register them in the project manifest. Keep the assumption on the
claim even if later formal work proves every consequence of the Boolean input.

## Review boundary

`EXAMPLE-IDENTITY-AX-001` is deliberately the understandable premise from the
allowance scenario:

> The external identity provider's `authorized = true` response correctly
> identifies the holder of the source account.

The review must inspect that precise scope. It does not attest to arithmetic
safety, byte encoding, provider uptime, account ownership outside this action,
or execution of a downstream transfer. `review_evidence` points to this anchor
so the assumption never has an empty review scope.

The test evidence remains `example-test`, and the claim remains dependent on an
active assumption. Neither a passing test nor a Lean theorem about the input
Boolean should render the external-provider premise as proved.
