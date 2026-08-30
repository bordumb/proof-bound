# PBCT canonical envelope version 1

All integers are unsigned and big-endian. An envelope is at most 4,104 bytes.

| Offset | Width | Meaning |
|---:|---:|---|
| 0 | 4 | ASCII magic `PBCT` |
| 4 | 1 | version, exactly `1` |
| 5 | 1 | reserved flags, exactly `0` |
| 6 | 2 | payload length, from `1` through `4096` |
| 8 | variable | exactly the declared number of opaque payload bytes |

The envelope ends after the payload. Short input and trailing bytes are
invalid. Because the length is fixed-width, reserved bits must be zero, and
the parser consumes the whole input, there is exactly one version-1 envelope
encoding for each accepted payload.

The payload is intentionally opaque here. A consumer defines and bounds its
own payload grammar and meaning rather than placing domain semantics in the
reusable envelope checker.
