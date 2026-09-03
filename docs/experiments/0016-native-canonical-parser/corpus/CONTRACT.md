# Frozen native proof and execution contract

## Verification conditions

The producer emits canonical SMT-LIB 2 containing five named scopes in this
order: `round-trip`, `malformed-rejection`, `canonicality`,
`exact-consumption`, and `bounded-termination`. Each scope asserts the
negation of its typed property and calls `check-sat`; the frozen expected result
is five `unsat` lines. Z3 is proof search, not the independent checker.

## Certificate

`proofbound-native-certificate/1` binds raw source and artifact SHA-256, the
artifact semantic identity, the exact five contract IDs, four value rows, all
156 byte inputs formed from alphabet `0..4` at lengths `0..3`, explicit scope,
the Z3 executable/version/input/result identities, and its own domain-separated
identity.

Value rows contain the value, encoded bytes, decoder result, consumption, and
step count. They constitute universal evidence only because `Value` is the
complete declared finite type. Input rows contain input bytes, success and
optional decoded value, optional canonical re-encoding, consumption, and step
count. They constitute bounded exhaustive evidence only for the registered
alphabet and maximum length.

The independent checker reparses source, recompiles exact bytecode, enumerates
both carriers, executes the VM, reconstructs every row, checks every contract,
and recomputes every identity. It reads the solver receipt but does not invoke
Z3 or accept the solver result as a substitute for the certificate.

## Semantic mutants

The six frozen alternatives are `accept-noncanonical`, `accept-trailing`,
`always-error`, `always-success`, `ignore-length`, and
`payload-substitution`. Each is an explicit alternate decoder relation checked
against the same five contracts and must have a deterministic first
counterexample. These are adequacy tests, not part of the accepted artifact.

## Assurance statement

The round-trip certificate is universal over all four inhabitants of the
declared `Value` type. The input properties are exhaustive only over 156
registered inputs. Examples remain tests. Z3 is an independently identified
proof-search tool. The bytecode corresponds to source through independent dual
compilation and exact bytes, not a verified compiler theorem. Consequently the
source may carry a proved finite-type round-trip fact while the artifact
remains assumption-bound rather than artifact-proved.
