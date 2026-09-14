from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/tool-bundle.yml"


def test_tool_bundle_workflow_is_exact_revision_and_verify_only() -> None:
    source = WORKFLOW.read_text()
    assert "workflow_dispatch:" in source
    assert "revision:" in source
    assert "verification_run_id:" in source
    assert "ref: ${{ env.PROOFBOUND_RELEASE_REVISION }}" in source
    assert 'test "$(git rev-parse HEAD)" = "$PROOFBOUND_RELEASE_REVISION"' in source
    assert "git merge-base --is-ancestor" in source
    assert 'gh api "/repos/$GITHUB_REPOSITORY/actions/runs/' in source
    assert '.name == "Verify"' in source
    assert '.event == "push"' in source
    assert '.head_branch == "main"' in source
    assert ".head_sha == $revision" in source
    assert '.conclusion == "success"' in source
    assert "permissions:\n  contents: read" in source
    assert "  actions: read" in source
    assert "gh release create" not in source
    assert "git tag" not in source


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


def test_tool_bundle_production_stays_after_the_full_verify_gate() -> None:
    specification = (ROOT / "docs/specs/0004_tool_bundle_distribution.md").read_text()
    assert "identified `Verify` run completed successfully" in specification
    assert "required independent approval" in specification
    assert "does not create or move a tag" in specification
