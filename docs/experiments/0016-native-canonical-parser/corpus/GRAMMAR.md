# Frozen native source grammar

The canonical source is UTF-8, LF-terminated, contains no blank lines, and has
exactly thirteen semicolon-terminated declarations in this order:

```text
module <kebab-id>;
type Value = range(<u8>, <u8>);
type Decode = result(Value, Error);
effect encode = pure;
effect decode = pure;
fn encode(value: Value) -> Bytes = bytes(<u8>, value);
fn decode(input: Bytes) -> Decode = match-exact(input, length=<u8>, prefix=<u8>, payload-max=<u8>, fallback=Error);
spec round-trip = forall value: Value => decode(encode(value)) == Ok(value);
spec malformed-rejection = forall input: BytesBounded => malformed(input) implies decode(input) == Error;
spec canonicality = forall input: BytesBounded => is-ok(decode(input)) implies encode(value-of(decode(input))) == input;
spec exact-consumption = forall input: BytesBounded => is-ok(decode(input)) implies consumed(input) == <u8>;
spec bounded-termination = forall input: BytesBounded => steps(decode(input)) <= length(input) + <u8>;
bound BytesBounded = bytes(alphabet=<u8>..<u8>, length=<u8>..<u8>);
```

The list above has thirteen forms because `module`, two `type`, two `effect`,
two `fn`, five `spec`, and one `bound` declaration total thirteen lines.
Identifiers are lowercase ASCII words separated by one hyphen. Decimal bytes
have no leading zero unless the value is zero.

`Value` must start at zero. The encoder prefix equals the decoder prefix, the
payload maximum equals the `Value` maximum, exact consumption equals decoder
length, and the byte bound must be `alphabet=0..4, length=0..3`. Both functions
are pure. The `fallback=Error` branch makes decoding total. No loop, recursion,
foreign call, environment, file, clock, random, network, or write construct
exists in this language fragment.

The five specification expressions are parsed into closed constructors. Their
names, quantifiers, types, implications, operations, and constants are part of
the AST; a compiler may not fill them from an implicit template. The
specification-adequacy evidence is the frozen EXP-0014 suite and mutant set.
