from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def run_tool(path: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / path), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_root_version_is_synchronized() -> None:
    result = run_tool("tools/ci/version.py", "--check")
    assert result.returncode == 0, result.stderr


def test_changelog_covers_current_version() -> None:
    result = run_tool("tools/ci/changelog.py")
    assert result.returncode == 0, result.stderr


def test_set_version_updates_every_derived_declaration(tmp_path: Path) -> None:
    (tmp_path / "crate").mkdir()
    (tmp_path / "docs/specs").mkdir(parents=True)
    (tmp_path / "VERSION").write_text("0.1.0\n")
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crate"]\n\n[workspace.package]\nversion = "0.1.0"\n'
    )
    (tmp_path / "crate/Cargo.toml").write_text(
        '[package]\nname = "example"\nversion.workspace = true\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        'version = 4\n\n[[package]]\nname = "example"\nversion = "0.1.0"\n'
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "proofbound"\nversion = "0.1.0"\n'
    )
    (tmp_path / "lakefile.toml").write_text('name = "proofbound"\nversion = "0.1.0"\n')
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "proofbound"\nversion = "0.1.0"\n'
        'source = { editable = "." }\n'
    )
    (tmp_path / "docs/specs/0001_initial_spec.md").write_text(
        "# Specification\n\n**Version:** 0.1.0\n"
    )

    result = run_tool("tools/ci/version.py", "--root", str(tmp_path), "--set", "1.2.3")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "VERSION").read_text() == "1.2.3\n"
    for relative in [
        "Cargo.toml",
        "Cargo.lock",
        "pyproject.toml",
        "lakefile.toml",
        "uv.lock",
    ]:
        assert 'version = "1.2.3"' in (tmp_path / relative).read_text()
    assert (
        "**Version:** 1.2.3"
        in (tmp_path / "docs/specs/0001_initial_spec.md").read_text()
    )


def test_staged_version_bump_requires_changelog_update(tmp_path: Path) -> None:
    (tmp_path / "VERSION").write_text("0.1.0\n")
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-01-01\n"
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "VERSION", "CHANGELOG.md"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Proofbound Test",
            "-c",
            "user.email=proofbound-test@invalid.local",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=tmp_path,
        check=True,
    )

    (tmp_path / "VERSION").write_text("0.2.0\n")
    subprocess.run(["git", "add", "VERSION"], cwd=tmp_path, check=True)
    rejected = run_tool("tools/ci/changelog.py", "--root", str(tmp_path), "--staged")
    assert rejected.returncode == 1
    assert "must stage CHANGELOG.md" in rejected.stderr

    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-01-02\n"
        "\n## [0.1.0] - 2026-01-01\n"
    )
    subprocess.run(["git", "add", "CHANGELOG.md"], cwd=tmp_path, check=True)
    accepted = run_tool("tools/ci/changelog.py", "--root", str(tmp_path), "--staged")
    assert accepted.returncode == 0, accepted.stderr
