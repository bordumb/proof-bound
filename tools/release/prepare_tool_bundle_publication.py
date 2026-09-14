#!/usr/bin/env python3
"""Validate two hosted tool-bundle candidates and stage one public release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.release import build_tool_bundle as bundle  # noqa: E402


PUBLICATION_SCHEMA = "proofbound-tool-bundle-publication-manifest/1"
PUBLICATION_MANIFEST = "TOOL-BUNDLE-PUBLICATION.json"
CHECKSUMS_NAME = "SHA256SUMS"
INSTALLER_NAME = "install-proofbound-tools.py"
REPOSITORY_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})"
)
MAX_SIDECAR_BYTES = 8 * 1024 * 1024
PLATFORMS = ("linux-aarch64", "linux-x86_64")


class PublicationError(ValueError):
    """One fail-closed publication preparation error."""


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _read_regular_file(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise PublicationError(f"publication input is not regular: {path.name}")
            data = source.read(limit + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise PublicationError(f"cannot read publication input: {path.name}") from error
    if len(data) > limit:
        raise PublicationError(f"publication input is too large: {path.name}")
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or after.st_size != len(data)
    ):
        raise PublicationError(f"publication input changed while read: {path.name}")
    return data


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _candidate_name(platform: str, revision: str) -> str:
    return f"proofbound-tools-{platform}-{revision}"


def _archive_name(platform: str, revision: str) -> str:
    return f"proofbound-tools-{revision}-{platform}.tar.gz"


def _manifest_name(platform: str, revision: str) -> str:
    return f"proofbound-tools-{revision}-{platform}.manifest.json"


def _parse_checksums(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise PublicationError("candidate checksums are not ASCII") from error
    records: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,255})", line
        )
        if match is None or match.group(2) in records:
            raise PublicationError("candidate checksums are not a canonical unique set")
        records[match.group(2)] = match.group(1)
    if not records or text != "".join(
        f"{digest}  {name}\n" for name, digest in records.items()
    ):
        raise PublicationError("candidate checksums are not canonical")
    return records


def _regular_inventory(directory: Path) -> tuple[str, ...]:
    if directory.is_symlink() or not directory.is_dir():
        raise PublicationError(f"candidate directory is invalid: {directory.name}")
    names: list[str] = []
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise PublicationError(f"candidate member is not regular: {path.name}")
        names.append(path.name)
    return tuple(sorted(names))


def _artifact_record(name: str, data: bytes, role: str) -> dict[str, object]:
    return {
        "name": name,
        "role": role,
        "sha256": f"sha256:{_digest(data)}",
        "size_bytes": len(data),
    }


def prepare(
    root: Path,
    candidates: Path,
    output: Path,
    revision: str,
    verification_run_id: int,
    bundle_workflow_run_id: int,
    producer_repository: str,
) -> dict[str, object]:
    """Validate both candidate platforms and stage a closed release directory."""

    if bundle.REVISION_PATTERN.fullmatch(revision) is None:
        raise PublicationError("the source revision is not 40 lowercase hex characters")
    if verification_run_id < 1 or bundle_workflow_run_id < 1:
        raise PublicationError("workflow run identities must be positive integers")
    if REPOSITORY_PATTERN.fullmatch(producer_repository) is None:
        raise PublicationError("the producer repository identity is invalid")
    if candidates.is_symlink() or not candidates.is_dir():
        raise PublicationError("the candidate root is not a regular directory")
    observed_candidates = tuple(sorted(path.name for path in candidates.iterdir()))
    expected_candidates = tuple(
        sorted(_candidate_name(item, revision) for item in PLATFORMS)
    )
    if observed_candidates != expected_candidates:
        raise PublicationError("the candidate platform inventory is not exact")
    if output.exists():
        if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
            raise PublicationError("the publication output directory is not empty")
    else:
        output.mkdir(parents=True)

    release_bytes: dict[str, tuple[bytes, str]] = {}
    installer_bytes: bytes | None = None
    for platform in PLATFORMS:
        candidate = candidates / _candidate_name(platform, revision)
        archive_name = _archive_name(platform, revision)
        expected_inventory = tuple(
            sorted((CHECKSUMS_NAME, bundle.MANIFEST_NAME, INSTALLER_NAME, archive_name))
        )
        if _regular_inventory(candidate) != expected_inventory:
            raise PublicationError(f"candidate inventory is not exact: {platform}")

        checksums_bytes = _read_regular_file(
            candidate / CHECKSUMS_NAME, MAX_SIDECAR_BYTES
        )
        checksums = _parse_checksums(checksums_bytes)
        expected_checksums = {archive_name, bundle.MANIFEST_NAME, INSTALLER_NAME}
        if set(checksums) != expected_checksums:
            raise PublicationError(
                f"candidate checksum inventory is not exact: {platform}"
            )

        archive_path = candidate / archive_name
        archive_manifest = bundle.verify_archive(archive_path, checksums[archive_name])
        if (
            archive_manifest["source_revision"] != revision
            or archive_manifest["verification_run_id"] != verification_run_id
            or archive_manifest["platform"] != platform
        ):
            raise PublicationError(f"candidate identity differs: {platform}")

        manifest_bytes = _read_regular_file(
            candidate / bundle.MANIFEST_NAME, bundle.MAX_MANIFEST_BYTES
        )
        if _digest(manifest_bytes) != checksums[bundle.MANIFEST_NAME]:
            raise PublicationError(f"detached manifest digest differs: {platform}")
        if manifest_bytes != bundle._canonical_json(archive_manifest):
            raise PublicationError(
                f"detached manifest differs from archive: {platform}"
            )

        candidate_installer = _read_regular_file(
            candidate / INSTALLER_NAME, MAX_SIDECAR_BYTES
        )
        if _digest(candidate_installer) != checksums[INSTALLER_NAME]:
            raise PublicationError(f"installer digest differs: {platform}")
        if candidate_installer != _read_regular_file(
            root / bundle.INSTALLER_SOURCE, MAX_SIDECAR_BYTES
        ):
            raise PublicationError(
                f"installer differs from reviewed source: {platform}"
            )
        if installer_bytes is not None and candidate_installer != installer_bytes:
            raise PublicationError("candidate installers differ between platforms")
        installer_bytes = candidate_installer

        archive_bytes = bundle._read_archive_bytes(archive_path)
        release_bytes[archive_name] = (archive_bytes, "archive")
        release_bytes[_manifest_name(platform, revision)] = (
            manifest_bytes,
            "bundle-manifest",
        )

    if installer_bytes is None:
        raise PublicationError("the verified installer inventory is empty")
    release_bytes[INSTALLER_NAME] = (installer_bytes, "installer")
    release_tag = f"proofbound-tools-{revision}"
    publication = {
        "assets": [
            _artifact_record(name, data, role)
            for name, (data, role) in sorted(release_bytes.items())
        ],
        "bundle_workflow_run_id": bundle_workflow_run_id,
        "producer_repository": producer_repository,
        "release_tag": release_tag,
        "schema": PUBLICATION_SCHEMA,
        "source_revision": revision,
        "verification_run_id": verification_run_id,
    }
    publication_bytes = _canonical_json(publication)
    release_bytes[PUBLICATION_MANIFEST] = (publication_bytes, "publication-manifest")
    for name, (data, _) in release_bytes.items():
        destination = output / name
        destination.write_bytes(data)
        destination.chmod(0o755 if name == INSTALLER_NAME else 0o644)
    checksums_bytes = "".join(
        f"{_digest(data)}  {name}\n"
        for name, (data, _) in sorted(release_bytes.items())
    ).encode("ascii")
    (output / CHECKSUMS_NAME).write_bytes(checksums_bytes)
    (output / CHECKSUMS_NAME).chmod(0o644)
    return publication


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--verification-run-id", type=int, required=True)
    parser.add_argument("--bundle-workflow-run-id", type=int, required=True)
    parser.add_argument("--producer-repository", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        result = prepare(
            args.root.resolve(),
            args.candidates.absolute(),
            args.output.absolute(),
            args.revision,
            args.verification_run_id,
            args.bundle_workflow_run_id,
            args.producer_repository,
        )
    except (OSError, PublicationError, bundle.BundleError) as error:
        print(f"tool bundle publication rejected: {error}", file=sys.stderr)
        return 1
    print(_canonical_json(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
