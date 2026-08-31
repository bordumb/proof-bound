from __future__ import annotations

import subprocess
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RESOLVER = REPOSITORY_ROOT / ".github/scripts/resolve-assurance-base.sh"


def git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def commit(repository: Path, value: str) -> str:
    (repository / "state.txt").write_text(value, encoding="utf-8")
    git(repository, "add", "state.txt")
    git(repository, "commit", "-m", value)
    return git(repository, "rev-parse", "HEAD")


def resolve(
    repository: Path,
    event: str,
    event_base: str,
    event_before: str,
    ref_name: str,
    default_branch: str,
    head: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            str(RESOLVER),
            event,
            event_base,
            event_before,
            ref_name,
            default_branch,
            head,
        ],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


def feature_history(repository: Path) -> tuple[str, str, str]:
    git(repository, "init", "--quiet", "--initial-branch", "main")
    git(repository, "config", "user.name", "Proofbound Test")
    git(repository, "config", "user.email", "proofbound@example.invalid")
    git(repository, "config", "commit.gpgsign", "false")
    reviewed_base = commit(repository, "reviewed base")
    git(repository, "update-ref", "refs/remotes/origin/main", reviewed_base)
    git(repository, "switch", "--quiet", "-c", "feature")
    previous_feature_tip = commit(repository, "previous feature tip")
    commit(repository, "documentation commit")
    commit(repository, "reviewed subject")
    envelope_head = commit(repository, "approval envelope")
    return reviewed_base, previous_feature_tip, envelope_head


def test_pr_and_feature_push_use_the_same_stable_review_base(tmp_path: Path) -> None:
    reviewed_base, previous_feature_tip, envelope_head = feature_history(tmp_path)

    pull_request = resolve(
        tmp_path,
        "pull_request",
        reviewed_base,
        "",
        "1/merge",
        "main",
        envelope_head,
    )
    assert pull_request.returncode == 0, pull_request.stderr
    assert pull_request.stdout.strip() == reviewed_base

    feature_push = resolve(
        tmp_path,
        "push",
        "",
        previous_feature_tip,
        "feature",
        "main",
        envelope_head,
    )
    assert feature_push.returncode == 0, feature_push.stderr
    assert feature_push.stdout.strip() == reviewed_base
    assert feature_push.stdout.strip() != previous_feature_tip


def test_default_push_uses_before_and_missing_default_ref_fails_closed(
    tmp_path: Path,
) -> None:
    reviewed_base, previous_feature_tip, envelope_head = feature_history(tmp_path)
    git(tmp_path, "update-ref", "refs/remotes/origin/main", envelope_head)

    default_push = resolve(
        tmp_path,
        "push",
        "",
        previous_feature_tip,
        "main",
        "main",
        envelope_head,
    )
    assert default_push.returncode == 0, default_push.stderr
    assert default_push.stdout.strip() == previous_feature_tip

    git(tmp_path, "update-ref", "-d", "refs/remotes/origin/main")
    missing_default = resolve(
        tmp_path,
        "push",
        "",
        previous_feature_tip,
        "feature",
        "main",
        envelope_head,
    )
    assert missing_default.returncode == 2
    assert "origin/main is unavailable" in missing_default.stderr
    assert reviewed_base != previous_feature_tip


def test_schedule_and_release_compare_with_the_fetched_default_branch(
    tmp_path: Path,
) -> None:
    reviewed_base, previous_feature_tip, envelope_head = feature_history(tmp_path)

    for event in ("schedule", "release"):
        feature_event = resolve(
            tmp_path,
            event,
            "",
            "",
            "feature",
            "main",
            envelope_head,
        )
        assert feature_event.returncode == 0, feature_event.stderr
        assert feature_event.stdout.strip() == reviewed_base

    git(tmp_path, "update-ref", "refs/remotes/origin/main", envelope_head)
    default_snapshot = resolve(
        tmp_path,
        "schedule",
        "",
        "",
        "main",
        "main",
        envelope_head,
    )
    assert default_snapshot.returncode == 0, default_snapshot.stderr
    assert default_snapshot.stdout.strip() == envelope_head

    git(tmp_path, "update-ref", "-d", "refs/remotes/origin/main")
    missing_default = resolve(
        tmp_path,
        "release",
        "",
        "",
        "v1.0.0",
        "main",
        envelope_head,
    )
    assert missing_default.returncode == 2
    assert "origin/main is unavailable" in missing_default.stderr
    assert reviewed_base != previous_feature_tip


def test_missing_event_revisions_and_disconnected_history_fail_closed(
    tmp_path: Path,
) -> None:
    _, previous_feature_tip, envelope_head = feature_history(tmp_path)
    zero = "0" * 40

    for missing_base in ("", zero):
        pull_request = resolve(
            tmp_path,
            "pull_request",
            missing_base,
            "",
            "1/merge",
            "main",
            envelope_head,
        )
        assert pull_request.returncode == 2
        assert "pull-request base revision is missing" in pull_request.stderr

    for missing_before in ("", zero):
        default_push = resolve(
            tmp_path,
            "push",
            "",
            missing_before,
            "main",
            "main",
            envelope_head,
        )
        assert default_push.returncode == 2
        assert "default-branch push base revision is missing" in default_push.stderr

    unsupported = resolve(
        tmp_path,
        "workflow_dispatch",
        "",
        "",
        "feature",
        "main",
        envelope_head,
    )
    assert unsupported.returncode == 2
    assert "unsupported GitHub event" in unsupported.stderr

    git(tmp_path, "switch", "--orphan", "disconnected")
    disconnected_head = commit(tmp_path, "disconnected history")
    disconnected = resolve(
        tmp_path,
        "push",
        "",
        previous_feature_tip,
        "feature",
        "main",
        disconnected_head,
    )
    assert disconnected.returncode == 2
    assert "have no merge base" in disconnected.stderr
