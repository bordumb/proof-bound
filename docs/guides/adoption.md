# Adoption guide

Start with `proofbound init`. The generated Tier 0 ledger asks you to replace a
clearly marked statement with a claim your software already makes, bind the
tests you already run, and record known assumptions and exclusions. No Lean or
Kani installation is required.

For brownfield software, inventory claims before trying to prove them. A useful
first board is mostly `TESTED`, with external dependencies listed as
`ASSUMED` and missing guarantees listed as `OPEN`. Promote one high-value claim
at a time:

1. Add a finite Kani or exhaustive domain for `BOUNDED_CHECKED`.
2. Add an attributed Lean theorem and compiled axiom audit for `PROVED · MODEL_ONLY`.
3. Add source refinement or byte/digest binding for a shipping claim.

Do not delete a weaker evidence record when a stronger one lands. Its scope and
mutation sensitivity remain useful review information.

Every claim report ends with “not proved / out of scope.” Read that section as
part of the claim, not as release-note fine print.

