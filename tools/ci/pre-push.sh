#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if remote_head="$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD)"; then
  default_branch="${remote_head#origin/}"
elif git rev-parse --verify refs/remotes/origin/main^{commit} >/dev/null 2>&1; then
  default_branch="main"
else
  printf 'pre-push failed: origin/HEAD and origin/main are unavailable\n' >&2
  exit 2
fi
current_branch="$(git symbolic-ref --quiet --short HEAD)" || {
  printf 'pre-push failed: detached HEAD is not supported\n' >&2
  exit 2
}
base="$(
  bash .github/scripts/resolve-assurance-base.sh \
    push \
    "" \
    "" \
    "refs/heads/$current_branch" \
    "$default_branch" \
    HEAD
)"

cargo build --locked --offline -q -p proofbound-cli
target/debug/proofbound diff "$base..HEAD" --json
