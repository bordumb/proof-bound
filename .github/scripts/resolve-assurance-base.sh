#!/usr/bin/env bash
set -euo pipefail

event_name="${1:-}"
event_base="${2:-}"
event_before="${3:-}"
event_ref="${4:-}"
default_branch="${5:-}"
requested_head="${6:-HEAD}"
zero_revision="0000000000000000000000000000000000000000"

fail() {
  printf 'assurance base resolution failed: %s\n' "$1" >&2
  exit 2
}

head="$(git rev-parse --verify "${requested_head}^{commit}")" \
  || fail "event head is not a commit"

case "$event_name" in
  pull_request)
    candidate="$event_base"
    if [[ -z "$candidate" || "$candidate" == "$zero_revision" ]]; then
      fail "pull-request base revision is missing"
    fi
    ;;
  push)
    if [[ -z "$default_branch" ]]; then
      fail "repository default branch is missing"
    fi
    if [[ "$event_ref" == "refs/heads/$default_branch" ]]; then
      candidate="$event_before"
      if [[ -z "$candidate" || "$candidate" == "$zero_revision" ]]; then
        fail "default-branch push base revision is missing"
      fi
      base="$(git rev-parse --verify "${candidate}^{commit}")" \
        || fail "default-branch push base is not a commit"
      printf '%s\n' "$base"
      exit 0
    else
      candidate="refs/remotes/origin/$default_branch"
      git rev-parse --verify "${candidate}^{commit}" >/dev/null \
        || fail "origin/$default_branch is unavailable"
    fi
    ;;
  schedule | release)
    if [[ -z "$default_branch" ]]; then
      fail "repository default branch is missing"
    fi
    candidate="refs/remotes/origin/$default_branch"
    git rev-parse --verify "${candidate}^{commit}" >/dev/null \
      || fail "origin/$default_branch is unavailable"
    ;;
  *)
    fail "unsupported GitHub event '$event_name'"
    ;;
esac

base="$(git merge-base "$candidate" "$head")" \
  || fail "event head and comparison base have no merge base"
printf '%s\n' "$base"
