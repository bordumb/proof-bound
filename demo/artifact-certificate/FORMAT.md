# PBAC certificate format, version 1

`PBAC` is a deliberately small, domain-neutral certificate format used by the
Proofbound artifact-soundness demo. The producer is untrusted. Acceptance is
defined entirely by the independent Rust and Lean decoders.

All offsets below are byte offsets. A version-1 certificate is:

| Bytes | Meaning |
|---|---|
| `50 42 41 43` | ASCII magic `PBAC` |
| `01` | format version |
| `00` | flags; every bit is reserved and must be zero |
| `01`..`08` | entry count |
| ULEB128 | claimed total, at most `1_000_000` |
| repeated | one-byte nonzero entry ID, then a ULEB128 value |

Entry IDs must be strictly increasing. Values are at most `1_000_000`. The
claimed total is accepted only when it equals the mathematical sum of every
entry value.

ULEB128 values use at most five bytes and must be minimal. In particular, a
multi-byte encoding whose final seven-bit group is zero is rejected. A fifth
byte may contain only the low four payload bits. There is no padding: any byte
after the final value is trailing data and is rejected.

The complete artifact is limited to 64 bytes before parsing. These rules give
every accepted certificate exactly one byte representation.

