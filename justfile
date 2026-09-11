set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

bootstrap:
    cargo fetch --locked
    uv sync --frozen
    lake build

fmt:
    cargo fmt --all -- --check

hooks:
    uvx --from pre-commit==4.5.1 pre-commit install --hook-type pre-commit --hook-type pre-push

fast-checks:
    bash tools/ci/pre-commit.sh

pre-push:
    bash tools/ci/pre-push.sh

set-version version:
    python3 tools/ci/version.py --set "{{version}}"

preflight:
    cargo xtask preflight

test: preflight

release-smoke:
    cargo xtask release-smoke

adapters:
    cargo xtask adapters

# Honest pre-first-commit gate: runs `just ci` in a disposable unrelated Git
# repository so clean-release checks stay strict without fabricating history.
bootstrap-ci:
    cargo xtask bootstrap-ci

lean:
    lake build

check:
    uv run --frozen cargo run --locked -q -p proofbound-cli -- check

status:
    uv run --frozen cargo run --locked -q -p proofbound-cli -- status

verify:
    cargo xtask ci

ci:
    cargo xtask ci
