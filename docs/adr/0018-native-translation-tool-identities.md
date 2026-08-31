# ADR 0018: Probe native translation-tool identities exactly

Status: accepted

## Context

Proofbound originally treated every executable as if it implemented a GNU-style
`--version` flag. The installed Charon and Aeneas CLIs do not: Charon exposes
`charon version`, while Aeneas exposes `aeneas -version`. Consequently `doctor`
reported both installed tools as missing, and the authoritative translation
adapter failed at the same probe boundary. The subsequent lock comparison used
substring matching, which could accept a prefix, suffix, or unrelated line that
merely contained the registered text.

The native commands also expose less than full build provenance. Charon
currently prints its package version, and Aeneas prints an abbreviated revision.
Neither output establishes the complete source commit, build recipe, or exact
executable bytes.

## Decision

- Invoke the exact native commands `charon version` and `aeneas -version` in
  both the CLI doctor and the Charon/Aeneas adapter.
- Accept an identity only when the process exits zero, stderr is empty, and
  bounded stdout is valid UTF-8 with exactly one nonempty line terminated by at
  most one LF. Reject CR, unknown, dirty, truncated, multiline, or otherwise
  malformed output.
- Require Charon's complete line to be a canonical three-component numeric
  version with no leading zeroes and treat it as the observable identity.
  Require the Aeneas line to have the exact form `aeneas <revision>`, where the
  revision is 7–40 lowercase hexadecimal characters, and use only that token.
  Compare each normalized identity to the corresponding version-1 lock field
  by equality. Prefix, suffix, and substring matches fail closed.
- Distinguish a missing executable from a process that cannot be spawned and
  from an installed executable with malformed native output. A valid native
  identity remains ready even when it differs from the project lock; the
  separate locked-toolchain capability is then unavailable and names the exact
  mismatch. Both tool readiness and project-capability availability are needed
  by a translation evidence unit.
- Keep `proofbound-translation-toolchain/1` for the first executable contract.
  Its historically named revision fields bind only the exact identities the
  native commands can reveal; they do not claim full source or build
  attestation.

## Consequences

Doctor output now describes the host truthfully, and the adapter checks the
same tools independently instead of trusting the CLI diagnosis. A version-1
lock cannot claim more provenance than the executables expose. If commit-level
or build-level provenance is required, a future lock version must add exact
executable digests or a separately verified build attestation; weakening an
unobservable full commit to prefix matching is not an acceptable substitute.
