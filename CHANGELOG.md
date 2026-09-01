# Changelog

All notable changes to Proofbound are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The root `VERSION` file is the release version source of truth.

## [Unreleased]

## [0.0.1] - 2026-09-01

### Added

- Theorem-derived artifact binding with independent statement-wire validation.
- Complete versioned receipt provenance, including assumptions, memory state,
  public and internal language, and full command/run inventories.
- Executable trusted-transcription evidence with separate transcriber and
  re-encoder trust roles.
- Exact adapter inventories and typed checker-result contracts.
- Sealed singleton mutation replay with exact baseline and expected-failure
  witnesses.
- Draft specifications for Python and TypeScript ecosystem support.
- Root `VERSION` synchronization, release metadata checks, and a fast local
  pre-commit gate.

### Changed

- Translation manifests now authoritatively register invocations, generated
  outputs, translated closures, imports, and bridge boundaries.
- Charon and Aeneas native identities are probed with their actual command-line
  interfaces and compared exactly.
- Assurance-regression reviews bind an immutable approval envelope to the
  exact reviewed subject commit.
- Experiment registration guidance now requires internally consistent and
  mathematically precise pass criteria.

### Security

- Artifact-bound status can no longer be created from checker-authored binding
  booleans.
- Passed adapter evidence requires exact nonempty inventories and successful
  observed process exits.
- Mutation replay binds the complete effective source tree, file permissions,
  semantic closure, claim subject, and registered preimage/postimage bytes.
- Cached evidence now fails closed across source, manifest, permission, tool,
  and receipt-shape drift.

[Unreleased]: https://github.com/bordumb/proof-bound/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/bordumb/proof-bound/releases/tag/v0.0.1
