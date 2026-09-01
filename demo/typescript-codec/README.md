# Proofbound TypeScript codec reference

This package is the Specification 0003 reference vertical. It deliberately has
no lifecycle scripts: vitest, strict TypeScript analysis, mutation replay, and
npm package reproduction are invoked only through Proofbound's typed routes.

The fast-check property uses seed `424242`, 100 examples, and byte arrays of at
most 256 bytes. It remains empirical evidence and does not establish an
unbounded theorem about the codec.

Install the exact dependency closure with `npm ci --ignore-scripts`, then run
`proofbound doctor`, `proofbound check`, `proofbound status`, and
`proofbound release`. The standalone `proofbound-verify` binary independently
recomputes the portable receipt's evidence identities, including both npm
package candidates and the registered digest.
