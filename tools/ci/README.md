# Local CI tools

This directory contains small, networkless checks shared by local development
and hosted CI.

- `version.py --check` verifies that every product version derived from the
  root `VERSION` file is synchronized.
- `version.py --set X.Y.Z` updates `VERSION`, the Rust/Python/Lean manifests,
  the workspace lockfiles, and the normative specification in one operation.
- `changelog.py` validates the changelog structure and current-version entry.
  `changelog.py --staged` additionally requires `VERSION` and `CHANGELOG.md`
  to be staged together for a release bump.
- `pre-commit.sh` runs the fast, proof-free subset of CI used by the local
  pre-commit hook.

Install the hook once with:

```console
uvx --from pre-commit==4.5.1 pre-commit install
```

Run it without committing with:

```console
uvx --from pre-commit==4.5.1 pre-commit run --all-files
```
