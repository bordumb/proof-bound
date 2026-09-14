# Specification 0004: Runtime-consumable tool bundles

**Status:** Draft; independent acceptance and publication remain open

**Date:** 2026-09-14

## 1. Purpose

Proofbound Runtime needs one immutable distribution identity for the
Proofbound CLI, independent verifier, and adapters used by its release gate.
This specification defines that distribution boundary. A tool bundle is a
delivery artifact. It is not a Proofbound assurance release and does not
upgrade the status of a claim.

## 2. Bundle identity

One bundle identifies:

- the exact 40-character lowercase source revision on Proofbound `main`;
- the exact successful main-branch `Verify` workflow run for that revision;
- one closed Linux platform tuple;
- the exact Rust toolchain channel;
- the complete ordered binary and schema payload; and
- the SHA-256 digest and byte size of each payload member.

Supported platform tuples are `linux-x86_64` and `linux-aarch64`. An absent
tuple is unsupported. The bundle schema is
`proofbound-tool-bundle-manifest/1`.

The manifest carries the current product label as informational build metadata.
The label is not a compatibility promise, release selector, or substitute for
the exact source, workflow-run, platform, toolchain, and payload identities.

The required binaries are:

- `proofbound`;
- `proofbound-verify`;
- `proofbound-adapter-aeneas`;
- `proofbound-adapter-kani`;
- `proofbound-adapter-lean`;
- `proofbound-adapter-node`; and
- `proofbound-adapter-test`.

The bundle contains every committed JSON Schema and CDDL file below
`schemas/`. It also contains `LICENSE`, `README.md`, and the release
verification guide. These files make the tool and its public wire contracts
available from one archive.

## 3. Production

The release workflow accepts one exact commit and one exact workflow-run
identity. It checks that the commit is on `main`, the checkout is clean, and
the identified `Verify` run completed successfully for a push of that exact
commit to `main`. It records the run identity in the bundle manifest. The
retained workflow artifacts are release candidates until the exact tag,
review, and publication steps are complete.

Each architecture builds the required binaries twice in independent target
directories with the locked dependency graph. The workflow requires exact
binary equality. It then creates the archive twice with normalized ownership,
permissions, ordering, and timestamps and requires exact archive equality.

The workflow uploads the archive, its detached manifest, the fail-closed
installer, and `SHA256SUMS`. It does not create or move a tag and does not
publish a versioned release. Prelaunch acceptance is attached to the exact
source revision and reproduced workflow artifacts after independent review.
Publication credentials are unavailable to pull-request workflows.

## 4. Consumption

A consumer must verify the archive digest before extraction. It must then
reject:

- a symbolic link, hard link, device, directory, or other non-regular member;
- an absolute path, parent traversal, duplicate path, unexpected archive root,
  or unexpected member;
- an unknown manifest field, schema, platform, or binary inventory;
- a missing, extra, substituted, or wrongly executable payload member; and
- a manifest digest or size that differs from the extracted bytes.

The installer refuses to replace an existing executable unless the operator
uses its explicit replacement option. It rejects a symlink in any existing
destination-path component and rejects an existing executable target that is
not a regular file or symlink. It writes only beneath the selected destination.
It rejects an archive larger than 256 MiB, an expanded payload larger than
512 MiB, or an inventory larger than 4,096 members before those bounds can be
exceeded.

## 5. Trust boundary

A digest identifies bytes. A source revision identifies repository state under
the repository controls. Neither authenticates the publisher before a separate
signing policy exists. The bundle trusts the identified compiler, linker, build
host, GitHub Actions runner, archive implementation, and release operator.
Those roles are not proved correct by reproducible bytes.

The bundled `proofbound-verify` remains independent of every other Proofbound
workspace crate. Bundling the executables together does not merge their
semantic implementations.

## 6. Required falsifiers

- Change one binary between the two builds.
- Add or remove one required executable.
- Add an undeclared archive member.
- Substitute one payload member after manifest creation.
- Add a path-traversal or link member.
- Change the source revision, verification-run identity, product label,
  platform, or toolchain identity.
- Identify a failed, incomplete, same-named wrong workflow, non-push,
  other-repository, or different-revision workflow run.
- Attempt release from a symbolic revision or a commit outside `main`.
- Attempt installation over an existing executable without explicit consent.
- Attempt installation through a symlinked destination ancestor or over an
  existing directory or special-file target.

## 7. Exit condition

This specification is implemented when both supported archives reproduce from
one independently approved exact source revision, their hosted checks pass,
Runtime installs the same bundle identities without a Git build, and an
unrelated consumer verifies the archives and their contained schemas.
