from __future__ import annotations

import hashlib
import io
from pathlib import Path
import sys
import tarfile
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.release import build_tool_bundle as bundle  # noqa: E402
from tools.release import install_tool_bundle as installer  # noqa: E402


REVISION = "1" * 40


def fake_artifacts() -> tuple[bundle.Artifact, ...]:
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


def fake_archive(
    tmp_path: Path,
    artifacts: tuple[bundle.Artifact, ...] | None = None,
) -> tuple[Path, str]:
    payload = artifacts or fake_artifacts()
    manifest = bundle._manifest(
        product_label="0.0.1",
        revision=REVISION,
        verification_run_id=123456,
        platform="linux-x86_64",
        rust_toolchain="1.94.0",
        artifacts=payload,
    )
    archive_bytes = bundle._archive_bytes(
        f"proofbound-tools-{REVISION}-linux-x86_64",
        1,
        payload,
        bundle._canonical_json(manifest),
    )
    path = tmp_path / "bundle.tar.gz"
    path.write_bytes(archive_bytes)
    return path, hashlib.sha256(archive_bytes).hexdigest()


def test_repository_tool_bundle_preflight_is_closed() -> None:
    product_label, toolchain = bundle.preflight(ROOT)
    assert product_label == (ROOT / "VERSION").read_text().strip()
    assert toolchain == "1.94.0"


def test_repository_payload_contains_the_complete_public_schema_inventory() -> None:
    binaries = {name: name.encode() for name in bundle.BINARY_NAMES}
    artifacts = bundle._payload(ROOT, binaries)
    paths = tuple(artifact.path for artifact in artifacts)
    expected_schemas = tuple(
        f"schemas/{path.name}"
        for path in (ROOT / "schemas").iterdir()
        if path.is_file()
    )
    assert tuple(sorted(expected_schemas)) == bundle.SCHEMA_PATHS
    assert installer.SCHEMA_PATHS == bundle.SCHEMA_PATHS
    assert installer.DOCUMENTS == bundle.DOCUMENTS
    assert installer.BINARY_NAMES == tuple(sorted(bundle.BINARY_NAMES))
    assert paths == bundle._allowed_payload_paths()


def test_archive_round_trip_checks_exact_payload(tmp_path: Path) -> None:
    path, digest = fake_archive(tmp_path)
    manifest = bundle.verify_archive(path, digest)
    assert manifest["schema"] == bundle.MANIFEST_SCHEMA
    assert manifest["source_revision"] == REVISION
    assert manifest["verification_run_id"] == 123456


def test_archive_digest_substitution_is_rejected(tmp_path: Path) -> None:
    path, _ = fake_archive(tmp_path)
    with pytest.raises(bundle.BundleError, match="archive digest"):
        bundle.verify_archive(path, "0" * 64)


def test_archive_validation_never_materializes_the_full_tar_inventory(
    tmp_path: Path,
) -> None:
    path, digest = fake_archive(tmp_path)
    with mock.patch.object(
        tarfile.TarFile,
        "getmembers",
        side_effect=AssertionError("full archive scan"),
    ):
        bundle.verify_archive(path, digest)
        installer.verify(path, digest)


def test_archive_member_limit_fails_during_streaming(tmp_path: Path) -> None:
    path, digest = fake_archive(tmp_path)
    with (
        mock.patch.object(bundle, "MAX_ARTIFACTS", 2),
        pytest.raises(bundle.BundleError, match="inventory is too large"),
    ):
        bundle.verify_archive(path, digest)
    with (
        mock.patch.object(installer, "MAX_ARTIFACTS", 2),
        pytest.raises(installer.InstallError, match="inventory is too large"),
    ):
        installer.verify(path, digest)


def test_invalid_verification_run_identity_is_rejected() -> None:
    manifest = bundle._manifest(
        product_label="0.0.1",
        revision=REVISION,
        verification_run_id=123456,
        platform="linux-x86_64",
        rust_toolchain="1.94.0",
        artifacts=fake_artifacts(),
    )
    manifest["verification_run_id"] = True
    with pytest.raises(bundle.BundleError, match="verification run identity"):
        bundle._validated_manifest(manifest)
    with pytest.raises(installer.InstallError, match="verification run identity"):
        installer._validate_manifest(manifest)


def test_payload_substitution_is_rejected(tmp_path: Path) -> None:
    path, _ = fake_archive(tmp_path)
    with tarfile.open(path, "r:gz") as source:
        members = source.getmembers()
        contents = {
            member.name: source.extractfile(member).read()
            for member in members
            if source.extractfile(member) is not None
        }
    attacked = tmp_path / "attacked.tar.gz"
    with tarfile.open(attacked, "w:gz") as destination:
        for member in members:
            data = contents[member.name]
            if member.name.endswith("/bin/proofbound"):
                data += b"attacked"
                member.size = len(data)
            destination.addfile(member, io.BytesIO(data))
    with pytest.raises(bundle.BundleError, match="artifact identity differs"):
        bundle.verify_archive(attacked)


def test_manifest_cannot_authorize_an_unexpected_payload_member(
    tmp_path: Path,
) -> None:
    artifacts = tuple(
        sorted(
            (*fake_artifacts(), bundle.Artifact("unexpected", b"extra", False)),
            key=lambda artifact: artifact.path,
        )
    )
    path, digest = fake_archive(tmp_path, artifacts)
    with pytest.raises(bundle.BundleError, match="payload inventory is not exact"):
        bundle.verify_archive(path, digest)
    with pytest.raises(installer.InstallError, match="payload inventory is not exact"):
        installer.verify(path, digest)


def test_undeclared_and_link_members_are_rejected(tmp_path: Path) -> None:
    path, _ = fake_archive(tmp_path)
    with tarfile.open(path, "r:gz") as source:
        members = source.getmembers()
        contents = {
            member.name: source.extractfile(member).read()
            for member in members
            if source.extractfile(member) is not None
        }
    for attack in ("undeclared", "link"):
        attacked = tmp_path / f"{attack}.tar.gz"
        with tarfile.open(attacked, "w:gz") as destination:
            for member in members:
                destination.addfile(member, io.BytesIO(contents[member.name]))
            if attack == "undeclared":
                data = b"extra"
                info = tarfile.TarInfo(
                    f"proofbound-tools-{REVISION}-linux-x86_64/extra"
                )
                info.size = len(data)
                destination.addfile(info, io.BytesIO(data))
            else:
                info = tarfile.TarInfo(f"proofbound-tools-{REVISION}-linux-x86_64/link")
                info.type = tarfile.SYMTYPE
                info.linkname = "bin/proofbound"
                destination.addfile(info)
        expected = "undeclared member" if attack == "undeclared" else "non-regular"
        with pytest.raises(bundle.BundleError, match=expected):
            bundle.verify_archive(attacked)


def test_build_rejects_binary_reproduction_drift(tmp_path: Path) -> None:
    first = {name: name.encode() for name in bundle.BINARY_NAMES}
    second = dict(first)
    second["proofbound"] = b"different"
    with (
        mock.patch.object(bundle, "preflight", return_value=("0.1.0", "1.94.0")),
        mock.patch.object(bundle, "_source_revision", return_value=(REVISION, 1)),
        mock.patch.object(bundle, "_platform", return_value="linux-x86_64"),
        mock.patch.object(bundle, "_build_once", side_effect=(first, second)),
        pytest.raises(bundle.BundleError, match="binary builds differ"),
    ):
        bundle.build(ROOT, tmp_path / "output", REVISION, 123456)


def test_build_rejects_nonempty_output_before_compilation(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "existing").write_text("preserve")
    with (
        mock.patch.object(bundle, "preflight", return_value=("0.1.0", "1.94.0")),
        mock.patch.object(bundle, "_source_revision", return_value=(REVISION, 1)),
        mock.patch.object(bundle, "_platform", return_value="linux-x86_64"),
        mock.patch.object(bundle, "_build_once") as build_once,
        pytest.raises(bundle.BundleError, match="output directory is not empty"),
    ):
        bundle.build(ROOT, output, REVISION, 123456)
    build_once.assert_not_called()


def test_installer_writes_only_the_verified_binary_inventory(tmp_path: Path) -> None:
    path, digest = fake_archive(tmp_path)
    destination = tmp_path / "bin"
    with mock.patch.object(installer, "_platform", return_value="linux-x86_64"):
        result = installer.install(path, digest, destination, False)
    assert result["source_revision"] == REVISION
    assert sorted(item.name for item in destination.iterdir()) == sorted(
        bundle.BINARY_NAMES
    )
    for name in bundle.BINARY_NAMES:
        installed = destination / name
        assert installed.read_bytes() == name.encode()
        assert installed.stat().st_mode & 0o777 == 0o755


def test_installer_stages_only_beneath_the_destination(tmp_path: Path) -> None:
    path, digest = fake_archive(tmp_path)
    destination = tmp_path / "bin"
    temporary_directory = installer.tempfile.TemporaryDirectory
    observed: list[Path] = []

    def recording_temporary_directory(*, prefix: str, dir: Path):
        observed.append(Path(dir))
        return temporary_directory(prefix=prefix, dir=dir)

    with (
        mock.patch.object(installer, "_platform", return_value="linux-x86_64"),
        mock.patch.object(
            installer.tempfile,
            "TemporaryDirectory",
            side_effect=recording_temporary_directory,
        ),
    ):
        installer.install(path, digest, destination, False)
    assert observed == [destination]


def test_installer_does_not_create_destination_ancestors(tmp_path: Path) -> None:
    path, digest = fake_archive(tmp_path)
    missing_parent = tmp_path / "missing"
    with (
        mock.patch.object(installer, "_platform", return_value="linux-x86_64"),
        pytest.raises(installer.InstallError, match="parent must already exist"),
    ):
        installer.install(path, digest, missing_parent / "bin", False)
    assert not missing_parent.exists()


def test_installer_requires_explicit_replacement(tmp_path: Path) -> None:
    path, digest = fake_archive(tmp_path)
    destination = tmp_path / "bin"
    destination.mkdir()
    existing = destination / "proofbound"
    existing.write_text("preserve")
    with (
        mock.patch.object(installer, "_platform", return_value="linux-x86_64"),
        pytest.raises(installer.InstallError, match="--replace"),
    ):
        installer.install(path, digest, destination, False)
    assert existing.read_text() == "preserve"
    assert list(destination.iterdir()) == [existing]


def test_installer_rejects_a_symlink_destination(tmp_path: Path) -> None:
    path, digest = fake_archive(tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    destination = tmp_path / "bin"
    destination.symlink_to(real, target_is_directory=True)
    with (
        mock.patch.object(installer, "_platform", return_value="linux-x86_64"),
        pytest.raises(installer.InstallError, match="symlink component"),
    ):
        installer.install(path, digest, destination, False)
    assert list(real.iterdir()) == []


def test_installer_cli_does_not_resolve_a_symlink_destination(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, digest = fake_archive(tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    destination = tmp_path / "bin"
    destination.symlink_to(real, target_is_directory=True)
    arguments = [
        "install_tool_bundle.py",
        "--archive",
        str(path),
        "--sha256",
        digest,
        "--destination",
        str(destination),
    ]
    with (
        mock.patch.object(installer, "_platform", return_value="linux-x86_64"),
        mock.patch.object(sys, "argv", arguments),
    ):
        assert installer.main() == 1
    assert "symlink component" in capsys.readouterr().err
    assert list(real.iterdir()) == []


def test_installer_rejects_a_symlink_destination_ancestor(tmp_path: Path) -> None:
    path, digest = fake_archive(tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real, target_is_directory=True)
    with (
        mock.patch.object(installer, "_platform", return_value="linux-x86_64"),
        pytest.raises(installer.InstallError, match="symlink component"),
    ):
        installer.install(path, digest, linked_parent / "bin", False)
    assert list(real.iterdir()) == []


def test_installer_rejects_an_existing_nonfile_target(tmp_path: Path) -> None:
    path, digest = fake_archive(tmp_path)
    destination = tmp_path / "bin"
    (destination / "proofbound").mkdir(parents=True)
    with (
        mock.patch.object(installer, "_platform", return_value="linux-x86_64"),
        pytest.raises(installer.InstallError, match="not replaceable files"),
    ):
        installer.install(path, digest, destination, True)
    assert (destination / "proofbound").is_dir()


def test_installer_rejects_a_cross_platform_bundle(tmp_path: Path) -> None:
    path, digest = fake_archive(tmp_path)
    with (
        mock.patch.object(installer, "_platform", return_value="linux-aarch64"),
        pytest.raises(installer.InstallError, match="differs from the host"),
    ):
        installer.install(path, digest, tmp_path / "bin", False)
