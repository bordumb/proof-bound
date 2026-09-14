from __future__ import annotations

from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/tool-bundle.yml"
sys.path.insert(0, str(ROOT))

from tools.release import validate_verification_run as run_validator  # noqa: E402


def test_tool_bundle_workflow_is_exact_revision_and_verify_only() -> None:
    source = WORKFLOW.read_text()
    assert "workflow_dispatch:" in source
    assert "group: proofbound-tool-bundle-${{ inputs.revision }}" in source
    assert "cancel-in-progress: false" in source
    assert "revision:" in source
    assert "verification_run_id:" in source
    assert "ref: ${{ env.PROOFBOUND_RELEASE_REVISION }}" in source
    assert 'test "$GITHUB_SHA" = "$PROOFBOUND_RELEASE_REVISION"' in source
    assert 'test "$GITHUB_WORKFLOW_SHA" = "$PROOFBOUND_RELEASE_REVISION"' in source
    assert 'test "$(git rev-parse HEAD)" = "$PROOFBOUND_RELEASE_REVISION"' in source
    assert "git merge-base --is-ancestor" in source
    assert 'gh api "/repos/$GITHUB_REPOSITORY/actions/runs/' in source
    assert 'gh api "/repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml"' in source
    assert "validate_verification_run.py" in source
    assert "permissions:\n  contents: read" in source
    assert "  actions: read" in source
    assert 'gh api --method POST "/repos/$GITHUB_REPOSITORY/releases"' in source
    assert '-f "target_commitish=$PROOFBOUND_RELEASE_REVISION"' in source
    assert "-f make_latest=false" in source
    assert "proofbound-tools-$PROOFBOUND_RELEASE_REVISION" in source
    assert "git tag" not in source


def test_same_name_wrong_workflow_is_rejected() -> None:
    workflow = {"id": 11, "name": "Verify", "path": ".github/workflows/ci.yml"}
    run = {
        "workflow_id": 12,
        "name": "Verify",
        "path": ".github/workflows/not-ci.yml",
        "event": "push",
        "head_branch": "main",
        "head_sha": "1" * 40,
        "status": "completed",
        "conclusion": "success",
    }
    with pytest.raises(run_validator.VerificationRunError, match="not the exact"):
        run_validator.validate(run, workflow, "1" * 40)


def test_tool_bundle_workflow_reproduces_both_supported_platforms() -> None:
    source = WORKFLOW.read_text()
    assert "platform: linux-x86_64\n            runner: ubuntu-24.04" in source
    assert "platform: linux-aarch64\n            runner: ubuntu-24.04-arm" in source
    assert "build_tool_bundle.py" in source
    assert "--expected-revision" in source
    assert "--verification-run-id" in source
    assert "sha256sum --check SHA256SUMS" in source
    assert "install_tool_bundle.py" in source
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in source


def test_tool_bundle_workflow_publishes_and_anonymously_rechecks_both_candidates() -> (
    None
):
    source = WORKFLOW.read_text()
    assert (
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in source
    )
    assert (
        "pattern: proofbound-tools-*-${{ env.PROOFBOUND_RELEASE_REVISION }}" in source
    )
    assert "prepare_tool_bundle_publication.py" in source
    assert "validate_tool_bundle_release.py" in source
    assert '.object.type + ":" + .object.sha' in source
    assert "-F draft=true" in source
    assert "--expected-state draft" in source
    assert "--expected-state published" in source
    assert '{ test "$state" = "draft"' in source
    assert 'test "$state" = "mutable-published"' in source
    assert 'state="publishing"' in source
    assert 'state="mutable-published"' in source
    assert 'state="published"' in source
    assert '"/repos/$GITHUB_REPOSITORY/immutable-releases"' not in source
    assert source.index('state="publishing"') < source.index("gh api --method PATCH")
    assert source.index('state="published"') > source.index("gh api --method PATCH")
    assert "published a mutable release; removing the exact owned release" in source
    assert 'gh api --method POST "/repos/$GITHUB_REPOSITORY/git/refs"' in source
    assert 'gh api --method POST "/repos/$GITHUB_REPOSITORY/releases"' in source
    assert 'gh release upload "$tag" dist/publication/*' in source
    assert '"/repos/$GITHUB_REPOSITORY/releases/$release_id"' in source
    assert 'test -n "$release_id"' in source
    assert "gh release view" not in source
    assert "git ls-remote" not in source
    assert (
        'test "$(gh api "/repos/$GITHUB_REPOSITORY" --jq .visibility)" = "public"'
        in source
    )
    assert "https://github.com/$GITHUB_REPOSITORY/releases/download/$tag" in source
    assert "cmp dist/publication/SHA256SUMS" in source
    assert "sha256sum --check SHA256SUMS" in source
    assert '"/repos/$GITHUB_REPOSITORY/releases/$release_id"' in source
    assert '"/repos/$GITHUB_REPOSITORY/git/refs/tags/$tag"' in source


def test_tool_bundle_production_stays_after_the_full_verify_gate() -> None:
    specification = (ROOT / "docs/specs/0004_tool_bundle_distribution.md").read_text()
    assert "`Verify` run completed successfully" in specification
    assert "independent review" in specification
    assert "exact source-identity tag" in specification
