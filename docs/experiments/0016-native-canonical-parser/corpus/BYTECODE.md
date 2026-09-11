# Frozen native bytecode `/1`

The artifact is exactly 22 bytes:

```text
offset  bytes                  meaning
0       50 42 56 4d            ASCII PBVM
4       01                     format version
5       04                     encoder section length
6       0b                     decoder section length
7       10 <prefix>            emit constant byte
9       11                     emit argument byte
10      ff                     return byte string
11      20 <length>            require exact input length
13      21 00 <prefix>         require byte at index 0
16      22 01 <payload-max>    require byte at index 1 at most maximum
19      23 01                  return byte at index 1
21      fe                     total fallback Error branch
```

Any failed decoder guard returns `Error`. Successful encoding consumes one
`Value`; successful decoding consumes the complete input. VM steps count each
executed opcode, including the guard that fails. The terminal fallback marker
is part of the totality certificate even though successful execution returns
before it.

The artifact raw SHA-256 binds exact bytes. Its semantic identity uses domain
`proofbound-native-bytecode/1` over those bytes. The independent checker
recompiles the source and requires exact artifact equality before executing it.
