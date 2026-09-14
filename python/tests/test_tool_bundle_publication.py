from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.release import build_tool_bundle as bundle  # noqa: E402
from tools.release import prepare_tool_bundle_publication as publication  # noqa: E402
from tools.release import validate_tool_bundle_release as release_check  # noqa: E402


REVISION = "1" * 40
VERIFICATION_RUN_ID = 123456
BUNDLE_RUN_ID = 234567
REPOSITORY = "bordumb/proof-bound"


def _fake_payload() -> tuple[bundle.Artifact, ...]:
    artifacts = [
        bundle.Artifact(f"bin/{name}", name.encode(), True)
        for name in bundle.BINARY_NAMES
    ]
    artifacts.extend(
        bundle.Artifact(path, path.encode(), False) for path in bundle.DOCUMENTS
    )
    artifacts.extend(
        bundle.Artifact(path, f"{path}\n".encode(), False)
        for path in bundle.SCHEMA_PATHS
    )
    return tuple(sorted(artifacts, key=lambda artifact: artifact.path))


def _candidate(candidates: Path, platform: str) -> Path:
    candidate = candidates / publication._candidate_name(platform, REVISION)
    candidate.mkdir(parents=True)
    manifest = bundle._manifest(
        product_label="0.0.1",
        revision=REVISION,
        verification_run_id=VERIFICATION_RUN_ID,
        platform=platform,
        rust_toolchain="1.94.0",
        artifacts=_fake_payload(),
    )
    manifest_bytes = bundle._canonical_json(manifest)
    archive_name = publication._archive_name(platform, REVISION)
    archive_bytes = bundle._archive_bytes(
        f"proofbound-tools-{REVISION}-{platform}",
        1,
        _fake_payload(),
        manifest_bytes,
    )
    installer_bytes = (ROOT / bundle.INSTALLER_SOURCE).read_bytes()
    (candidate / archive_name).write_bytes(archive_bytes)
    (candidate / bundle.MANIFEST_NAME).write_bytes(manifest_bytes)
    (candidate / publication.INSTALLER_NAME).write_bytes(installer_bytes)
    (candidate / publication.CHECKSUMS_NAME).write_text(
        f"{hashlib.sha256(archive_bytes).hexdigest()}  {archive_name}\n"
        f"{hashlib.sha256(installer_bytes).hexdigest()}  {publication.INSTALLER_NAME}\n"
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  {bundle.MANIFEST_NAME}\n",
        encoding="ascii",
    )
    return candidate


def _candidates(tmp_path: Path) -> Path:
    candidates = tmp_path / "candidates"
    for platform in publication.PLATFORMS:
        _candidate(candidates, platform)
    return candidates


def _prepare(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    output = tmp_path / "publication"
    result = publication.prepare(
        ROOT,
        _candidates(tmp_path),
        output,
        REVISION,
        VERIFICATION_RUN_ID,
        BUNDLE_RUN_ID,
        REPOSITORY,
    )
    return output, result


def _release_record(output: Path) -> dict[str, object]:
    assets = []
    for path in output.iterdir():
        data = path.read_bytes()
        assets.append(
            {
                "digest": f"sha256:{hashlib.sha256(data).hexdigest()}",
                "name": path.name,
                "size": len(data),
                "state": "uploaded",
            }
        )
    return {
        "assets": assets,
        "draft": False,
        "prerelease": False,
        "tag_name": f"proofbound-tools-{REVISION}",
        "target_commitish": REVISION,
    }


def test_publication_stages_one_closed_exact_identity(tmp_path: Path) -> None:
    output, result = _prepare(tmp_path)
    expected_names = {
        publication.CHECKSUMS_NAME,
        publication.INSTALLER_NAME,
        publication.PUBLICATION_MANIFEST,
        *(
            publication._archive_name(platform, REVISION)
            for platform in publication.PLATFORMS
        ),
        *(
            publication._manifest_name(platform, REVISION)
            for platform in publication.PLATFORMS
        ),
    }
    assert {path.name for path in output.iterdir()} == expected_names
    assert result["source_revision"] == REVISION
    assert result["verification_run_id"] == VERIFICATION_RUN_ID
    assert result["bundle_workflow_run_id"] == BUNDLE_RUN_ID
    assert result["release_tag"] == f"proofbound-tools-{REVISION}"
    assert len(result["assets"]) == 5
    assert (
        output / publication.PUBLICATION_MANIFEST
    ).read_bytes() == publication._canonical_json(result)
    checksums = publication._parse_checksums(
        (output / publication.CHECKSUMS_NAME).read_bytes()
    )
    assert set(checksums) == expected_names - {publication.CHECKSUMS_NAME}
    release_check.validate(
        _release_record(output),
        output,
        REVISION,
        VERIFICATION_RUN_ID,
        BUNDLE_RUN_ID,
        REPOSITORY,
    )
    schema = json.loads(
        (ROOT / "schemas/tool-bundle-publication-manifest.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(result)


def test_publication_rejects_missing_platform_and_unknown_candidate(
    tmp_path: Path,
) -> None:
    candidates = tmp_path / "candidates"
    _candidate(candidates, publication.PLATFORMS[0])
    with pytest.raises(publication.PublicationError, match="platform inventory"):
        publication.prepare(
            ROOT,
            candidates,
            tmp_path / "output",
            REVISION,
            VERIFICATION_RUN_ID,
            BUNDLE_RUN_ID,
            REPOSITORY,
        )
    (candidates / "unknown").mkdir()
    with pytest.raises(publication.PublicationError, match="platform inventory"):
        publication.prepare(
            ROOT,
            candidates,
            tmp_path / "output",
            REVISION,
            VERIFICATION_RUN_ID,
            BUNDLE_RUN_ID,
            REPOSITORY,
        )


def test_publication_rejects_detached_manifest_substitution(tmp_path: Path) -> None:
    candidates = _candidates(tmp_path)
    attacked = candidates / publication._candidate_name("linux-x86_64", REVISION)
    manifest_path = attacked / bundle.MANIFEST_NAME
    manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
    with pytest.raises(publication.PublicationError, match="manifest digest differs"):
        publication.prepare(
            ROOT,
            candidates,
            tmp_path / "output",
            REVISION,
            VERIFICATION_RUN_ID,
            BUNDLE_RUN_ID,
            REPOSITORY,
        )


def test_publication_rejects_platform_installer_divergence(tmp_path: Path) -> None:
    candidates = _candidates(tmp_path)
    attacked = candidates / publication._candidate_name("linux-x86_64", REVISION)
    installer = attacked / publication.INSTALLER_NAME
    installer.write_bytes(installer.read_bytes() + b"\n")
    checksums = publication._parse_checksums(
        (attacked / publication.CHECKSUMS_NAME).read_bytes()
    )
    checksums[publication.INSTALLER_NAME] = hashlib.sha256(
        installer.read_bytes()
    ).hexdigest()
    (attacked / publication.CHECKSUMS_NAME).write_text(
        "".join(f"{digest}  {name}\n" for name, digest in checksums.items()),
        encoding="ascii",
    )
    with pytest.raises(publication.PublicationError, match="reviewed source"):
        publication.prepare(
            ROOT,
            candidates,
            tmp_path / "output",
            REVISION,
            VERIFICATION_RUN_ID,
            BUNDLE_RUN_ID,
            REPOSITORY,
        )


def test_release_validation_rejects_identity_and_asset_attacks(tmp_path: Path) -> None:
    output, _ = _prepare(tmp_path)
    release = _release_record(output)
    release["target_commitish"] = "2" * 40
    with pytest.raises(release_check.ReleaseError, match="identity or state"):
        release_check.validate(
            release,
            output,
            REVISION,
            VERIFICATION_RUN_ID,
            BUNDLE_RUN_ID,
            REPOSITORY,
        )
    release = _release_record(output)
    release["assets"].append(
        {
            "digest": "sha256:" + "0" * 64,
            "name": "extra",
            "size": 0,
            "state": "uploaded",
        }
    )
    with pytest.raises(release_check.ReleaseError, match="inventory is not exact"):
        release_check.validate(
            release,
            output,
            REVISION,
            VERIFICATION_RUN_ID,
            BUNDLE_RUN_ID,
            REPOSITORY,
        )
    release = _release_record(output)
    release["assets"][0]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(release_check.ReleaseError, match="identity differs"):
        release_check.validate(
            release,
            output,
            REVISION,
            VERIFICATION_RUN_ID,
            BUNDLE_RUN_ID,
            REPOSITORY,
        )


def test_release_validation_rejects_staged_and_publication_manifest_attacks(
    tmp_path: Path,
) -> None:
    output, _ = _prepare(tmp_path)
    release = _release_record(output)
    (output / "extra").write_bytes(b"")
    release["assets"].append(
        {
            "digest": "sha256:" + "0" * 64,
            "name": "extra",
            "size": 0,
            "state": "uploaded",
        }
    )
    with pytest.raises(release_check.ReleaseError, match="staged.*not exact"):
        release_check.validate(
            release,
            output,
            REVISION,
            VERIFICATION_RUN_ID,
            BUNDLE_RUN_ID,
            REPOSITORY,
        )

    output, _ = _prepare(tmp_path / "second")
    publication_path = output / publication.PUBLICATION_MANIFEST
    manifest = json.loads(publication_path.read_text())
    manifest["source_revision"] = "2" * 40
    publication_path.write_bytes(publication._canonical_json(manifest))
    checksums = publication._parse_checksums(
        (output / publication.CHECKSUMS_NAME).read_bytes()
    )
    checksums[publication.PUBLICATION_MANIFEST] = hashlib.sha256(
        publication_path.read_bytes()
    ).hexdigest()
    (output / publication.CHECKSUMS_NAME).write_text(
        "".join(f"{digest}  {name}\n" for name, digest in checksums.items()),
        encoding="ascii",
    )
    release = _release_record(output)
    with pytest.raises(release_check.ReleaseError, match="manifest identity differs"):
        release_check.validate(
            release,
            output,
            REVISION,
            VERIFICATION_RUN_ID,
            BUNDLE_RUN_ID,
            REPOSITORY,
        )


def test_publication_entrypoints_work_without_pythonpath() -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    for script in (
        "tools/release/prepare_tool_bundle_publication.py",
        "tools/release/validate_tool_bundle_release.py",
    ):
        completed = subprocess.run(
            [sys.executable, script, "--help"],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
