# Changelog

All notable changes to Proofbound are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The root `VERSION` file is the release version source of truth.

## [Unreleased]

### Added

- Reviewed evidence contexts, exact release-artifact observations, and
  contextual semantic artifact bindings.
- Python and TypeScript static-analysis, property-test, mutation, and
  reproducible-distribution evidence routes.
- A reproducible Linux tool bundle containing the CLI, independent verifier,
  adapters, and public schemas, with a fail-closed installer.

### Changed

- The current compiled release and envelope schema is version 7. A claim now
  owns the exact bounded-domain identity used by its primary bounded evidence.
- The adapter subprocess protocol is version 2. Failed unit runs now retain a
  typed cause, timeout state, remediation, and executable identity.
- Lean theorem identity updates use reviewed corpus migrations, and assurance
  regression approvals bind the exact reviewed parent.

### Security

- The compiler and independent verifier enforce bounded-domain equality,
  exact artifact-observation sets, evidence contexts, and contextual binding
  membership independently.
- Timeout and protocol failures can no longer disappear behind a later missing
  evidence diagnostic.
- Tool bundles reject binary reproduction drift, unsafe archives, payload
  substitution, wrong-platform installation, and implicit executable
  replacement.

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
