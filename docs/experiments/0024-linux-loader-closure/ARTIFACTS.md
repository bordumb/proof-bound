# EXP-0024 artifacts

Canonical artifacts from GitHub Actions run 33811874795:

| Artifact | SHA-256 | Bytes |
|---|---|---:|
| `capture.json` | `29fc535db2638c978fbbfd5a37c2832ea9377a01749af22ee1fca91cffa79c5b` | 128,110 |
| `rust-report.json` | `a0bc4e4cc2d94f4d01400dacae941b6ddcf4be25e355bd6a59c6d8fd89d909fb` | 4,227 |
| `python-report.json` | `a0bc4e4cc2d94f4d01400dacae941b6ddcf4be25e355bd6a59c6d8fd89d909fb` | 4,227 |
| `attacks.json` | `65e37f8f415af1a69b0e230810c3d77271807bd32d223c81ee0e3568fb8afb90` | 4,694 |
| `execution.json` | `35d4d85c0804dafaef3155cd0d87ada637a8e62a281885c4ddcad8a955976ef6` | 802 |

The complete artifact bundle is attached to the successful workflow run as
`exp-0024-linux-loader-capture`. The exact objects remain execution artifacts
and are addressed by the digests above; this record does not silently
re-serialize them.
