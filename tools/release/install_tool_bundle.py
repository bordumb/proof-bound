#!/usr/bin/env python3
"""Verify and install binaries from one Proofbound tool bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform as host_platform
import re
import stat
import sys
import tarfile
import tempfile


MANIFEST_SCHEMA = "proofbound-tool-bundle-manifest/1"
MANIFEST_NAME = "TOOL-BUNDLE-MANIFEST.json"
BINARY_NAMES = (
    "proofbound",
    "proofbound-adapter-aeneas",
    "proofbound-adapter-kani",
    "proofbound-adapter-lean",
    "proofbound-adapter-node",
    "proofbound-adapter-test",
    "proofbound-verify",
)
DOCUMENTS = (
    "LICENSE",
    "README.md",
    "docs/guides/release-verification.md",
)
SUPPORTED_PLATFORMS = ("linux-aarch64", "linux-x86_64")
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_ARTIFACTS = 4096
MAX_TAR_STREAM_BYTES = MAX_EXPANDED_BYTES + ((MAX_ARTIFACTS + 1) * 1024) + 1024
SCHEMA_PATHS = (
    "schemas/README.md",
    "schemas/adapter-observation.schema.json",
    "schemas/adapter-protocol.schema.json",
    "schemas/assumption.schema.json",
    "schemas/checker-result.schema.json",
    "schemas/claim.schema.json",
    "schemas/closure.schema.json",
    "schemas/demo-registry.schema.json",
    "schemas/error.schema.json",
    "schemas/evidence-unit.schema.json",
    "schemas/evidence.schema.json",
    "schemas/graph.schema.json",
    "schemas/lean-expr-v1.cddl",
    "schemas/model-check-unit.schema.json",
    "schemas/mutation-registry.schema.json",
    "schemas/observation-inputs.schema.json",
    "schemas/policy.schema.json",
    "schemas/project.schema.json",
    "schemas/receipt.schema.json",
    "schemas/report.schema.json",
    "schemas/review.schema.json",
    "schemas/tcb.schema.json",
    "schemas/tool-bundle-manifest.schema.json",
    "schemas/tool-bundle-publication-manifest.schema.json",
    "schemas/translation-toolchain-lock.schema.json",
    "schemas/translation-unit.schema.json",
)


class InstallError(ValueError):
    """One fail-closed bundle verification or installation error."""


class _BoundedReader:
    """Limit bytes returned by one sequential decompression stream."""

    def __init__(self, source: gzip.GzipFile, limit: int) -> None:
        self._source = source
        self._limit = limit
        self._observed = 0

    def read(self, size: int = -1) -> bytes:
        """Read without permitting the configured byte limit to be crossed."""

        remaining = self._limit - self._observed
        requested = remaining + 1 if size < 0 or size > remaining + 1 else size
        data = self._source.read(requested)
        self._observed += len(data)
        if self._observed > self._limit:
            raise InstallError("the expanded tar stream is too large")
        return data


def _duplicate_guard(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InstallError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _safe_relative_path(value: str) -> bool:
    if not value or "\\" in value or len(value.encode()) > 4096:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(component not in {"", ".", ".."} for component in path.parts)
    )


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _allowed_payload_paths() -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                *(f"bin/{name}" for name in BINARY_NAMES),
                *DOCUMENTS,
                *SCHEMA_PATHS,
            )
        )
    )


def _platform() -> str:
    if sys.platform != "linux":
        raise InstallError("tool bundles are supported only on Linux")
    architecture = {"aarch64": "aarch64", "x86_64": "x86_64"}.get(
        host_platform.machine()
    )
    if architecture is None:
        raise InstallError("the host Linux architecture is unsupported")
    return f"linux-{architecture}"


def _read_archive_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise InstallError("the bundle archive is not a regular file")
            data = source.read(MAX_ARCHIVE_BYTES + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise InstallError(f"cannot read the bundle archive: {error}") from error
    if len(data) > MAX_ARCHIVE_BYTES:
        raise InstallError("the bundle archive is too large")
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or after.st_size != len(data)
    ):
        raise InstallError("the bundle archive changed while it was read")
    return data


def _validate_destination(destination: Path) -> None:
    for component in (*reversed(destination.parents), destination):
        if component.is_symlink():
            raise InstallError("the installation destination has a symlink component")
        if component.exists() and not component.is_dir():
            raise InstallError("the installation destination is not a real directory")


def _validate_manifest(value: object) -> tuple[dict[str, object], tuple[str, ...]]:
    if not isinstance(value, dict) or set(value) != {
        "artifacts",
        "platform",
        "product_label",
        "rust_toolchain",
        "schema",
        "source_revision",
        "verification_run_id",
    }:
        raise InstallError("the bundle manifest has an unknown field")
    if value.get("schema") != MANIFEST_SCHEMA:
        raise InstallError("the bundle manifest schema is unsupported")
    product_label = value.get("product_label")
    revision = value.get("source_revision")
    verification_run_id = value.get("verification_run_id")
    toolchain = value.get("rust_toolchain")
    if (
        not isinstance(product_label, str)
        or VERSION_PATTERN.fullmatch(product_label) is None
    ):
        raise InstallError("the bundle product label is invalid")
    if not isinstance(revision, str) or REVISION_PATTERN.fullmatch(revision) is None:
        raise InstallError("the bundle source revision is invalid")
    if (
        not isinstance(verification_run_id, int)
        or isinstance(verification_run_id, bool)
        or verification_run_id < 1
    ):
        raise InstallError("the bundle verification run identity is invalid")
    if value.get("platform") not in SUPPORTED_PLATFORMS:
        raise InstallError("the bundle platform is unsupported")
    if not isinstance(toolchain, str) or VERSION_PATTERN.fullmatch(toolchain) is None:
        raise InstallError("the bundle Rust toolchain is invalid")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not 0 < len(artifacts) <= MAX_ARTIFACTS:
        raise InstallError("the bundle artifact inventory is invalid")
    paths: list[str] = []
    binaries: list[str] = []
    for record in artifacts:
        if not isinstance(record, dict) or set(record) != {
            "executable",
            "path",
            "sha256",
            "size_bytes",
        }:
            raise InstallError("a bundle artifact record is malformed")
        path = record.get("path")
        digest = record.get("sha256")
        size = record.get("size_bytes")
        executable = record.get("executable")
        if not isinstance(path, str) or not _safe_relative_path(path):
            raise InstallError("a bundle artifact path is unsafe")
        if paths and path <= paths[-1]:
            raise InstallError("bundle artifact paths are not a strict lexical set")
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            raise InstallError(f"bundle artifact digest is invalid: {path}")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= MAX_EXPANDED_BYTES
        ):
            raise InstallError(f"bundle artifact size is invalid: {path}")
        if not isinstance(executable, bool) or executable != path.startswith("bin/"):
            raise InstallError(f"bundle artifact mode is invalid: {path}")
        paths.append(path)
        if path.startswith("bin/"):
            binaries.append(path.removeprefix("bin/"))
    if tuple(binaries) != BINARY_NAMES:
        raise InstallError("the required binary inventory is incomplete")
    if tuple(paths) != _allowed_payload_paths():
        raise InstallError("the bundle payload inventory is not exact")
    return value, tuple(paths)


def verify(
    path: Path, expected_sha256: str
) -> tuple[dict[str, object], dict[str, bytes]]:
    """Verify an archive and return its manifest and binary bytes."""

    expected = expected_sha256.removeprefix("sha256:")
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise InstallError("the expected archive digest is invalid")
    archive_bytes = _read_archive_bytes(path)
    if hashlib.sha256(archive_bytes).hexdigest() != expected:
        raise InstallError("the bundle archive digest differs")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(archive_bytes), mode="rb") as compressed:
            stream = _BoundedReader(compressed, MAX_TAR_STREAM_BYTES)
            with tarfile.open(fileobj=stream, mode="r|") as archive:
                contents: dict[str, tuple[tarfile.TarInfo, bytes]] = {}
                roots: set[str] = set()
                total_size = 0
                member_count = 0
                for member in archive:
                    member_count += 1
                    if member_count > MAX_ARTIFACTS + 1:
                        raise InstallError("the bundle archive inventory is too large")
                    if not member.isfile() or member.issym() or member.islnk():
                        raise InstallError(f"non-regular bundle member: {member.name}")
                    if not 0 <= member.size <= MAX_EXPANDED_BYTES:
                        raise InstallError(f"oversized bundle member: {member.name}")
                    total_size += member.size
                    if total_size > MAX_EXPANDED_BYTES:
                        raise InstallError("the expanded bundle is too large")
                    root, separator, relative = member.name.partition("/")
                    if (
                        not separator
                        or not _safe_relative_path(root)
                        or not _safe_relative_path(relative)
                    ):
                        raise InstallError(f"unsafe bundle member path: {member.name}")
                    roots.add(root)
                    if relative in contents:
                        raise InstallError(f"duplicate bundle member: {relative}")
                    source = archive.extractfile(member)
                    if source is None:
                        raise InstallError(f"bundle member has no bytes: {relative}")
                    data = source.read(member.size + 1)
                    if len(data) != member.size:
                        raise InstallError(f"bundle member size differs: {relative}")
                    contents[relative] = (member, data)
                if member_count <= 1:
                    raise InstallError("the bundle archive inventory is empty")
    except (OSError, tarfile.TarError) as error:
        raise InstallError(f"cannot parse the bundle archive: {error}") from error
    if len(roots) != 1 or MANIFEST_NAME not in contents:
        raise InstallError("the bundle archive root or manifest is invalid")
    manifest_bytes = contents[MANIFEST_NAME][1]
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise InstallError("the bundle manifest is too large")
    try:
        decoded = json.loads(manifest_bytes, object_pairs_hook=_duplicate_guard)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise InstallError(f"cannot parse the bundle manifest: {error}") from error
    manifest, paths = _validate_manifest(decoded)
    if _canonical_json(manifest) != manifest_bytes:
        raise InstallError("the bundle manifest is not canonical JSON")
    expected_root = (
        f"proofbound-tools-{manifest['source_revision']}-{manifest['platform']}"
    )
    if roots != {expected_root}:
        raise InstallError("the archive root differs from its manifest identity")
    if set(contents) != {MANIFEST_NAME, *paths}:
        raise InstallError("the bundle archive contains a missing or extra member")
    binaries: dict[str, bytes] = {}
    for record in manifest["artifacts"]:
        assert isinstance(record, dict)
        relative = str(record["path"])
        member, data = contents[relative]
        observed = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if observed != record["sha256"] or len(data) != record["size_bytes"]:
            raise InstallError(f"bundle artifact identity differs: {relative}")
        mode = 0o755 if record["executable"] else 0o644
        if member.mode & 0o777 != mode:
            raise InstallError(f"bundle artifact mode differs: {relative}")
        if relative.startswith("bin/"):
            binaries[relative.removeprefix("bin/")] = data
    return manifest, binaries


def install(
    archive: Path,
    expected_sha256: str,
    destination: Path,
    replace: bool,
) -> dict[str, object]:
    """Verify and install a complete executable inventory."""

    manifest, binaries = verify(archive, expected_sha256)
    if manifest["platform"] != _platform():
        raise InstallError("the bundle platform differs from the host platform")
    destination = Path(os.path.abspath(destination))
    _validate_destination(destination)
    if not destination.exists() and not destination.parent.is_dir():
        raise InstallError("the installation destination parent must already exist")
    destination.mkdir(exist_ok=True)
    targets = {name: destination / name for name in BINARY_NAMES}
    invalid_targets = [
        name
        for name, path in targets.items()
        if path.exists() and not path.is_file() and not path.is_symlink()
    ]
    if invalid_targets:
        raise InstallError(
            "existing executable paths are not replaceable files: "
            + ", ".join(invalid_targets)
        )
    existing = [
        name for name, path in targets.items() if path.exists() or path.is_symlink()
    ]
    if existing and not replace:
        raise InstallError(
            f"existing executables require --replace: {', '.join(existing)}"
        )
    with tempfile.TemporaryDirectory(
        prefix=".proofbound-install.", dir=destination
    ) as raw:
        stage = Path(raw)
        for name in BINARY_NAMES:
            path = stage / name
            path.write_bytes(binaries[name])
            path.chmod(0o755)
        for name in BINARY_NAMES:
            os.replace(stage / name, targets[name])
    return {
        "installed": [str(targets[name]) for name in BINARY_NAMES],
        "platform": manifest["platform"],
        "product_label": manifest["product_label"],
        "schema": MANIFEST_SCHEMA,
        "source_revision": manifest["source_revision"],
        "verification_run_id": manifest["verification_run_id"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    try:
        result = install(
            args.archive.resolve(),
            args.sha256,
            Path(os.path.abspath(args.destination)),
            args.replace,
        )
    except (InstallError, OSError) as error:
        print(f"tool bundle installation rejected: {error}", file=sys.stderr)
        return 1
    print(_canonical_json(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
