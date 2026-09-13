# Experiment 0025 retained results

[Conclusion](../CONCLUSION.md) · [Artifact ledger](../ARTIFACTS.md)

The checked-in files retain the compact canonical decision, one of the two
byte-identical independent reports, and one of the two byte-identical attack
reports from [GitHub run 33822698555](https://github.com/bordumb/proof-bound/actions/runs/33822698555).

The workflow artifact additionally contains the 446,835-byte raw capture, both
independent report files, both independent attack files, and the 30 mutated
captures. The raw capture is intentionally not copied into Git. Its SHA-256 is
`788ac34ab729a1efb40ee9d9b28e0365ac3c95c893353fdfa6a9eeaa1fa7aee3`.

| File | Retained payload bytes | Retained payload SHA-256 | Meaning |
|---|---:|---|---|
| `execution.json` | 1,151 | `4ad22d37227556486e5f8240c442bba31aaaf896660ac2d97f87c6766402e426` | Final decision and question outcomes |
| `report.json` | 4,043 | `c6353e8c0a3387818c031bd4e0ff3146a6d2c846948855007253374a65a797d3` | Byte-identical Python/Rust semantic report |
| `attacks.json` | 3,305 | `03262296e05c8c9019effb7ed0e203d1ae19e9f062bc896a9e9f92a2db91bbf2` | Byte-identical Python/Rust 30-attack report |

These hashes describe the retained compact payloads before Git's conventional
final newline. The semantic JSON values are unchanged in the checked-in copies.
