#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

python3 tools/ci/version.py --check
python3 tools/ci/changelog.py --staged
git diff --cached --check

cargo fmt --all -- --check
cargo fmt --manifest-path templates/artifact-checker/rust/Cargo.toml -- --check
cargo fmt --manifest-path templates/rust-aeneas-refinement/rust/Cargo.toml -- --check

cargo test --locked --offline -p proofbound-manifest --test repository_bundle
cargo test --locked --offline -p proofbound-manifest --test repository_closures
cargo test --locked --offline -p proofbound-ir-prototype

uv run --frozen --offline pytest -q \
  python/tests/test_public_schemas.py \
  python/tests/test_ci_revision_range.py \
  python/tests/test_assurance_ir_checker.py \
  python/tests/test_release_metadata.py
