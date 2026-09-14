#!/usr/bin/env python3
"""Build and verify a reproducible Proofbound Linux tool bundle."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform as host_platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib


MANIFEST_SCHEMA = "proofbound-tool-bundle-manifest/1"
MANIFEST_NAME = "TOOL-BUNDLE-MANIFEST.json"
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARTIFACTS = 4096
MAX_TAR_STREAM_BYTES = MAX_ARTIFACT_BYTES + ((MAX_ARTIFACTS + 1) * 1024) + 1024

BINARY_PACKAGES = (
    ("proofbound-cli", "proofbound"),
    ("proofbound-verify", "proofbound-verify"),
    ("proofbound-adapter-aeneas", "proofbound-adapter-aeneas"),
    ("proofbound-adapter-kani", "proofbound-adapter-kani"),
    ("proofbound-adapter-lean", "proofbound-adapter-lean"),
    ("proofbound-adapter-node", "proofbound-adapter-node"),
    ("proofbound-adapter-test", "proofbound-adapter-test"),
)
BINARY_NAMES = tuple(binary for _, binary in BINARY_PACKAGES)
DOCUMENTS = (
    "LICENSE",
    "README.md",
    "docs/guides/release-verification.md",
)
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
    "schemas/translation-toolchain-lock.schema.json",
    "schemas/translation-unit.schema.json",
)
INSTALLER_SOURCE = "tools/release/install_tool_bundle.py"
SUPPORTED_PLATFORMS = ("linux-aarch64", "linux-x86_64")


class BundleError(ValueError):
    """One fail-closed bundle production or verification error."""


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
            raise BundleError("the expanded tar stream is too large")
        return data


@dataclass(frozen=True)
class Artifact:
    """One exact payload member."""

    path: str
    data: bytes
    executable: bool

    def manifest_record(self) -> dict[str, object]:
        """Return this artifact's canonical manifest record."""

        return {
            "executable": self.executable,
            "path": self.path,
            "sha256": f"sha256:{hashlib.sha256(self.data).hexdigest()}",
            "size_bytes": len(self.data),
        }


def _run(arguments: list[str], *, root: Path, environment: dict[str, str]) -> None:
    try:
        subprocess.run(
            arguments,
            cwd=root,
            env=environment,
            check=True,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise BundleError(f"command failed: {arguments[0]}") from error


def _capture(arguments: list[str], *, root: Path) -> str:
    try:
        completed = subprocess.run(
            arguments,
            cwd=root,
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise BundleError(f"command failed: {arguments[0]}") from error
    return completed.stdout.strip()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"duplicate JSON key: {key}")
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


def _platform() -> str:
    if sys.platform != "linux":
        raise BundleError("tool bundles are supported only on Linux")
    architecture = {"aarch64": "aarch64", "x86_64": "x86_64"}.get(
        host_platform.machine()
    )
    if architecture is None:
        raise BundleError("unsupported Linux architecture")
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
                raise BundleError("the bundle archive is not a regular file")
            data = source.read(MAX_ARCHIVE_BYTES + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise BundleError(f"cannot read bundle archive: {error}") from error
    if len(data) > MAX_ARCHIVE_BYTES:
        raise BundleError("the bundle archive is too large")
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or after.st_size != len(data)
    ):
        raise BundleError("the bundle archive changed while it was read")
    return data


def _read_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as source:
            value = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise BundleError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise BundleError(f"invalid TOML document: {path}")
    return value


def preflight(root: Path) -> tuple[str, str]:
    """Validate bundle metadata and return the product label and toolchain."""

    try:
        product_label = (root / "VERSION").read_text(encoding="ascii").strip()
        toolchain = _read_toml(root / "rust-toolchain.toml")["toolchain"]
        workspace = _read_toml(root / "Cargo.toml")["workspace"]
    except (OSError, KeyError) as error:
        raise BundleError(f"missing bundle metadata: {error}") from error
    if VERSION_PATTERN.fullmatch(product_label) is None:
        raise BundleError("VERSION is not a canonical three-part product label")
    if not isinstance(toolchain, dict) or toolchain.get("channel") is None:
        raise BundleError("rust-toolchain.toml has no toolchain channel")
    rust_toolchain = str(toolchain["channel"])
    if VERSION_PATTERN.fullmatch(rust_toolchain) is None:
        raise BundleError("the Rust toolchain is not an exact three-part version")
    if not isinstance(workspace, dict) or not isinstance(
        workspace.get("members"), list
    ):
        raise BundleError("Cargo.toml has no closed workspace member inventory")
    members = set(workspace["members"])
    for package, _ in BINARY_PACKAGES:
        member = f"crates/{package}"
        if member not in members:
            raise BundleError(f"required bundle package is absent: {package}")
        manifest = _read_toml(root / member / "Cargo.toml")
        package_table = manifest.get("package")
        if not isinstance(package_table, dict) or package_table.get("name") != package:
            raise BundleError(f"package identity mismatch: {package}")
    schema = root / "schemas/tool-bundle-manifest.schema.json"
    if not schema.is_file() or schema.is_symlink():
        raise BundleError("the tool-bundle schema is unavailable")
    return product_label, rust_toolchain


def _source_revision(root: Path, expected_revision: str | None) -> tuple[str, int]:
    revision = _capture(["git", "rev-parse", "HEAD"], root=root)
    if REVISION_PATTERN.fullmatch(revision) is None:
        raise BundleError("Git did not return a canonical source revision")
    if expected_revision is not None and revision != expected_revision:
        raise BundleError(
            "the checked out revision differs from the requested revision"
        )
    if _capture(["git", "status", "--porcelain", "--untracked-files=all"], root=root):
        raise BundleError("tool bundles require a clean source tree")
    raw_epoch = _capture(["git", "show", "-s", "--format=%ct", revision], root=root)
    try:
        epoch = int(raw_epoch)
    except ValueError as error:
        raise BundleError("Git returned a nonnumeric source timestamp") from error
    if epoch < 0:
        raise BundleError("Git returned a negative source timestamp")
    return revision, epoch


def _build_environment(epoch: int) -> dict[str, str]:
    environment = os.environ.copy()
    removed = {
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_INCREMENTAL",
        "CARGO_TARGET_DIR",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "SOURCE_DATE_EPOCH",
    }
    for name in tuple(environment):
        if name in removed or (
            name.startswith("CARGO_TARGET_")
            and (name.endswith("_LINKER") or name.endswith("_RUSTFLAGS"))
        ):
            environment.pop(name)
    environment["CARGO_INCREMENTAL"] = "0"
    environment["SOURCE_DATE_EPOCH"] = str(epoch)
    return environment


def _build_once(root: Path, target: Path, epoch: int) -> dict[str, bytes]:
    arguments = ["cargo", "build", "--release", "--frozen", "--target-dir", str(target)]
    for package, _ in BINARY_PACKAGES:
        arguments.extend(("-p", package))
    _run(arguments, root=root, environment=_build_environment(epoch))
    binaries: dict[str, bytes] = {}
    for _, binary in BINARY_PACKAGES:
        path = target / "release" / binary
        try:
            binaries[binary] = path.read_bytes()
        except OSError as error:
            raise BundleError(f"cannot read built binary: {binary}") from error
    return binaries


def _payload(root: Path, binaries: dict[str, bytes]) -> tuple[Artifact, ...]:
    artifacts: list[Artifact] = []
    for binary in BINARY_NAMES:
        if binary not in binaries:
            raise BundleError(f"built binary is absent: {binary}")
        artifacts.append(Artifact(f"bin/{binary}", binaries[binary], True))
    for relative in DOCUMENTS:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise BundleError(f"required bundle document is unavailable: {relative}")
        artifacts.append(Artifact(relative, path.read_bytes(), False))
    schemas = sorted((root / "schemas").iterdir(), key=lambda path: path.name)
    observed_schema_paths = tuple(f"schemas/{path.name}" for path in schemas)
    if observed_schema_paths != SCHEMA_PATHS:
        raise BundleError("the public schema inventory differs from the closed bundle")
    for path in schemas:
        if path.is_symlink() or not path.is_file():
            raise BundleError(f"invalid schema inventory member: {path.name}")
        if path.name != "README.md" and path.suffix not in {".json", ".cddl"}:
            raise BundleError(f"unknown schema file type: {path.name}")
        artifacts.append(Artifact(f"schemas/{path.name}", path.read_bytes(), False))
    paths = [artifact.path for artifact in artifacts]
    if (
        len(paths) > MAX_ARTIFACTS
        or paths != sorted(paths)
        or len(paths) != len(set(paths))
    ):
        artifacts.sort(key=lambda artifact: artifact.path)
        paths = [artifact.path for artifact in artifacts]
    if len(paths) > MAX_ARTIFACTS or len(paths) != len(set(paths)):
        raise BundleError("bundle payload paths are not a bounded unique set")
    return tuple(artifacts)


def _allowed_payload_paths() -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                *(f"bin/{binary}" for binary in BINARY_NAMES),
                *DOCUMENTS,
                *SCHEMA_PATHS,
            )
        )
    )


def _manifest(
    *,
    product_label: str,
    revision: str,
    verification_run_id: int,
    platform: str,
    rust_toolchain: str,
    artifacts: tuple[Artifact, ...],
) -> dict[str, object]:
    return {
        "artifacts": [artifact.manifest_record() for artifact in artifacts],
        "platform": platform,
        "product_label": product_label,
        "rust_toolchain": rust_toolchain,
        "schema": MANIFEST_SCHEMA,
        "source_revision": revision,
        "verification_run_id": verification_run_id,
    }


def _archive_bytes(
    root_name: str,
    epoch: int,
    artifacts: tuple[Artifact, ...],
    manifest_bytes: bytes,
) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
        ) as archive:
            members = (*artifacts, Artifact(MANIFEST_NAME, manifest_bytes, False))
            for artifact in sorted(members, key=lambda item: item.path):
                info = tarfile.TarInfo(f"{root_name}/{artifact.path}")
                info.size = len(artifact.data)
                info.mode = 0o755 if artifact.executable else 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = epoch
                archive.addfile(info, io.BytesIO(artifact.data))
    return output.getvalue()


def _validated_manifest(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise BundleError("the bundle manifest is not an object")
    expected_keys = {
        "artifacts",
        "platform",
        "product_label",
        "rust_toolchain",
        "schema",
        "source_revision",
        "verification_run_id",
    }
    if set(value) != expected_keys or value.get("schema") != MANIFEST_SCHEMA:
        raise BundleError("the bundle manifest has an unknown field or schema")
    product_label = value.get("product_label")
    revision = value.get("source_revision")
    verification_run_id = value.get("verification_run_id")
    platform = value.get("platform")
    toolchain = value.get("rust_toolchain")
    if (
        not isinstance(product_label, str)
        or VERSION_PATTERN.fullmatch(product_label) is None
    ):
        raise BundleError("the bundle product label is invalid")
    if not isinstance(revision, str) or REVISION_PATTERN.fullmatch(revision) is None:
        raise BundleError("the bundle source revision is invalid")
    if (
        not isinstance(verification_run_id, int)
        or isinstance(verification_run_id, bool)
        or verification_run_id < 1
    ):
        raise BundleError("the bundle verification run identity is invalid")
    if platform not in SUPPORTED_PLATFORMS:
        raise BundleError("the bundle platform is unsupported")
    if not isinstance(toolchain, str) or VERSION_PATTERN.fullmatch(toolchain) is None:
        raise BundleError("the bundle Rust toolchain is invalid")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not 0 < len(artifacts) <= MAX_ARTIFACTS:
        raise BundleError("the bundle artifact inventory is empty or too large")
    previous = ""
    observed_binaries: list[str] = []
    observed_paths: set[str] = set()
    for record in artifacts:
        if not isinstance(record, dict) or set(record) != {
            "executable",
            "path",
            "sha256",
            "size_bytes",
        }:
            raise BundleError("a bundle artifact record is malformed")
        path = record.get("path")
        digest = record.get("sha256")
        size = record.get("size_bytes")
        executable = record.get("executable")
        if (
            not isinstance(path, str)
            or not _safe_relative_path(path)
            or path <= previous
        ):
            raise BundleError("bundle artifact paths are not a strict lexical set")
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            raise BundleError(f"bundle artifact digest is invalid: {path}")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= MAX_ARTIFACT_BYTES
        ):
            raise BundleError(f"bundle artifact size is invalid: {path}")
        if not isinstance(executable, bool) or executable != path.startswith("bin/"):
            raise BundleError(f"bundle executable mode is invalid: {path}")
        if path.startswith("bin/"):
            observed_binaries.append(path.removeprefix("bin/"))
        observed_paths.add(path)
        previous = path
    if tuple(observed_binaries) != tuple(sorted(BINARY_NAMES)):
        raise BundleError("the required binary inventory is incomplete")
    if tuple(sorted(observed_paths)) != _allowed_payload_paths():
        raise BundleError("the bundle payload inventory is not exact")
    return value


def verify_archive(path: Path, expected_sha256: str | None = None) -> dict[str, object]:
    """Verify one complete tool-bundle archive and return its manifest."""

    archive_bytes = _read_archive_bytes(path)
    digest = hashlib.sha256(archive_bytes).hexdigest()
    if expected_sha256 is not None:
        expected = expected_sha256.removeprefix("sha256:")
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None or digest != expected:
            raise BundleError(
                "the bundle archive digest differs from the expected identity"
            )
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
                        raise BundleError("the bundle archive inventory is too large")
                    if not member.isfile() or member.issym() or member.islnk():
                        raise BundleError(f"non-regular bundle member: {member.name}")
                    if not 0 <= member.size <= MAX_ARTIFACT_BYTES:
                        raise BundleError(f"oversized bundle member: {member.name}")
                    total_size += member.size
                    if total_size > MAX_ARTIFACT_BYTES:
                        raise BundleError("the expanded bundle is too large")
                    root, separator, relative = member.name.partition("/")
                    if (
                        not separator
                        or not _safe_relative_path(root)
                        or not _safe_relative_path(relative)
                    ):
                        raise BundleError(f"unsafe bundle member path: {member.name}")
                    roots.add(root)
                    if relative in contents:
                        raise BundleError(f"duplicate bundle member: {relative}")
                    source = archive.extractfile(member)
                    if source is None:
                        raise BundleError(f"bundle member has no bytes: {relative}")
                    data = source.read(member.size + 1)
                    if len(data) != member.size:
                        raise BundleError(f"bundle member size differs: {relative}")
                    contents[relative] = (member, data)
                if member_count <= 1:
                    raise BundleError("the bundle archive inventory is empty")
    except (OSError, tarfile.TarError) as error:
        raise BundleError(f"cannot parse bundle archive: {error}") from error
    if len(roots) != 1 or MANIFEST_NAME not in contents:
        raise BundleError("the bundle archive root or manifest is invalid")
    manifest_bytes = contents[MANIFEST_NAME][1]
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise BundleError("the bundle manifest is too large")
    try:
        decoded = json.loads(manifest_bytes, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise BundleError(f"cannot parse the bundle manifest: {error}") from error
    manifest = _validated_manifest(decoded)
    if _canonical_json(manifest) != manifest_bytes:
        raise BundleError("the bundle manifest is not canonical JSON")
    expected_root = (
        f"proofbound-tools-{manifest['source_revision']}-{manifest['platform']}"
    )
    if roots != {expected_root}:
        raise BundleError("the archive root differs from its manifest identity")
    expected_paths = {MANIFEST_NAME}
    for record in manifest["artifacts"]:
        assert isinstance(record, dict)
        relative = str(record["path"])
        expected_paths.add(relative)
        if relative not in contents:
            raise BundleError(f"bundle artifact is absent: {relative}")
        member, data = contents[relative]
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if len(data) != record["size_bytes"] or digest != record["sha256"]:
            raise BundleError(f"bundle artifact identity differs: {relative}")
        expected_mode = 0o755 if record["executable"] else 0o644
        if member.mode & 0o777 != expected_mode:
            raise BundleError(f"bundle artifact mode differs: {relative}")
    if set(contents) != expected_paths:
        raise BundleError("the bundle archive contains an undeclared member")
    return manifest


def build(
    root: Path,
    output: Path,
    expected_revision: str | None,
    verification_run_id: int,
) -> Path:
    """Build, reproduce, and retain one exact host-platform tool bundle."""

    product_label, rust_toolchain = preflight(root)
    revision, epoch = _source_revision(root, expected_revision)
    platform = _platform()
    if output.exists() and any(output.iterdir()):
        raise BundleError("the bundle output directory is not empty")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="proofbound-tool-bundle.") as directory:
        work = Path(directory)
        first = _build_once(root, work / "first", epoch)
        second = _build_once(root, work / "second", epoch)
        if first != second:
            raise BundleError("the independent binary builds differ")
        artifacts = _payload(root, first)
        manifest = _manifest(
            product_label=product_label,
            revision=revision,
            verification_run_id=verification_run_id,
            platform=platform,
            rust_toolchain=rust_toolchain,
            artifacts=artifacts,
        )
        manifest_bytes = _canonical_json(manifest)
        root_name = f"proofbound-tools-{revision}-{platform}"
        first_archive = _archive_bytes(root_name, epoch, artifacts, manifest_bytes)
        second_archive = _archive_bytes(root_name, epoch, artifacts, manifest_bytes)
        if first_archive != second_archive:
            raise BundleError("the independent archive productions differ")
        archive_path = output / f"{root_name}.tar.gz"
        archive_path.write_bytes(first_archive)
        manifest_path = output / MANIFEST_NAME
        manifest_path.write_bytes(manifest_bytes)
        installer_bytes = (root / INSTALLER_SOURCE).read_bytes()
        installer_path = output / "install-proofbound-tools.py"
        installer_path.write_bytes(installer_bytes)
        installer_path.chmod(0o755)
        verify_archive(archive_path, hashlib.sha256(first_archive).hexdigest())
        checksums = (
            f"{hashlib.sha256(first_archive).hexdigest()}  {archive_path.name}\n"
            f"{hashlib.sha256(installer_bytes).hexdigest()}  {installer_path.name}\n"
            f"{hashlib.sha256(manifest_bytes).hexdigest()}  {manifest_path.name}\n"
        )
        (output / "SHA256SUMS").write_text(checksums, encoding="ascii")
    return archive_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--output", type=Path)
    action.add_argument("--verify-archive", type=Path)
    parser.add_argument("--expected-revision")
    parser.add_argument("--verification-run-id", type=int)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[2])
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.check:
            product_label, rust_toolchain = preflight(root)
            result: object = {
                "accepted": True,
                "rust_toolchain": rust_toolchain,
                "schema": MANIFEST_SCHEMA,
                "product_label": product_label,
            }
        elif args.output is not None:
            if (
                args.expected_revision is not None
                and REVISION_PATTERN.fullmatch(args.expected_revision) is None
            ):
                raise BundleError(
                    "--expected-revision must be 40 lowercase hex characters"
                )
            if args.verification_run_id is None or args.verification_run_id < 1:
                raise BundleError("--verification-run-id must be a positive integer")
            archive = build(
                root,
                args.output.resolve(),
                args.expected_revision,
                args.verification_run_id,
            )
            result = {
                "accepted": True,
                "archive": str(archive),
                "schema": MANIFEST_SCHEMA,
            }
        else:
            assert args.verify_archive is not None
            result = verify_archive(args.verify_archive, args.expected_sha256)
    except (BundleError, OSError) as error:
        print(f"tool bundle rejected: {error}", file=sys.stderr)
        return 1
    print(_canonical_json(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
