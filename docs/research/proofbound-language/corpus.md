# Proofbound language research corpus

[Programme dashboard](README.md)

This registry identifies research subjects. Exact commit, release, toolchain,
and local-change identities are pinned by each experiment before execution.
External source remains outside Proofbound history.

| ID | Subject | Kind | Primary research role | Repository location |
|---|---|---|---|---|
| CORPUS-PY-001 | Python inventory service | controlled Python | Examples, sampled property, static check, mutation, wheel reproduction | `demo/python-inventory-service/` |
| CORPUS-TS-001 | TypeScript codec | controlled TypeScript | Examples, sampled property, static check, mutation, npm reproduction | `demo/typescript-codec/` |
| CORPUS-RS-001 | Allowance kernel | controlled Rust/Lean | Translation, refinement, mutation, theorem linkage | `demo/allowance/` |
| CORPUS-LEAN-001 | Artifact certificate | controlled Lean/Rust | Theorem, axiom audit, artifact binding | `demo/artifact-certificate/` |
| CORPUS-CONF-001 | Portable status graph corpus | controlled wire | Producer/verifier derivation parity and adversarial mutations | `proofbound/conformance/v1/status-graphs.json` |
| CORPUS-REL-001 | Release-valid fixture | controlled release | Canonical release and standalone verification | `proofbound/conformance/v1/release-valid/` |
| CORPUS-EXT-PY-001 | Click | external Python | Parametrized pytest identifiers | `other_repos/` when present; pin per experiment |
| CORPUS-EXT-PY-002 | ItsDangerous | external Python | Security library and opaque pytest identifiers | `other_repos/` when present; pin per experiment |
| CORPUS-EXT-PY-003 | attrs | external Python | Independent property-based project | `other_repos/` when present; pin per experiment |
| CORPUS-EXT-PY-004 | HTTPX | external Python | Broad package and test closure | `other_repos/` when present; pin per experiment |
| CORPUS-EXT-TS-001 | Vitest Coverage Report Action | external TypeScript | Library/action packaging and Vitest | `other_repos/` when present; pin per experiment |
| CORPUS-EXT-TS-002 | Node TypeScript Boilerplate | external TypeScript | Application-style layout and declared Node runtime | `other_repos/` when present; pin per experiment |

## Admission rules

A corpus entry must identify its license, exact source identity, role, local
modifications, and toolchain in the experiment that executes it. Similar
projects from one maintainer do not count as ecosystem variety.
