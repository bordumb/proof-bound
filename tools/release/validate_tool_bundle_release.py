#!/usr/bin/env python3
"""Validate GitHub release metadata against a staged tool-bundle publication."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.release import prepare_tool_bundle_publication as publication  # noqa: E402


DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


class ReleaseError(ValueError):
    """One fail-closed hosted release validation error."""


def _decode_json(data: bytes, name: str) -> object:
    try:
        return json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ReleaseError(f"cannot parse JSON: {name}") from error


def _load_json(path: Path) -> object:
    data = publication._read_regular_file(path, publication.MAX_SIDECAR_BYTES)
    return _decode_json(data, path.name)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _expected_names(revision: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                publication.CHECKSUMS_NAME,
                publication.INSTALLER_NAME,
                publication.PUBLICATION_MANIFEST,
                *(
                    publication._archive_name(platform, revision)
                    for platform in publication.PLATFORMS
                ),
                *(
                    publication._manifest_name(platform, revision)
                    for platform in publication.PLATFORMS
                ),
            )
        )
    )


def _role(name: str, revision: str) -> str:
    if name == publication.INSTALLER_NAME:
        return "installer"
    if name in {
        publication._archive_name(platform, revision)
        for platform in publication.PLATFORMS
    }:
        return "archive"
    if name in {
        publication._manifest_name(platform, revision)
        for platform in publication.PLATFORMS
    }:
        return "bundle-manifest"
    raise ReleaseError(f"unknown publication payload role: {name}")


def _validate_publication_manifest(
    staged: Path,
    revision: str,
    verification_run_id: int,
    bundle_workflow_run_id: int,
    producer_repository: str,
) -> None:
    manifest_path = staged / publication.PUBLICATION_MANIFEST
    manifest_bytes = publication._read_regular_file(
        manifest_path, publication.MAX_SIDECAR_BYTES
    )
    manifest = _decode_json(manifest_bytes, manifest_path.name)
    expected_keys = {
        "assets",
        "bundle_workflow_run_id",
        "producer_repository",
        "release_tag",
        "schema",
        "source_revision",
        "verification_run_id",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        raise ReleaseError("the publication manifest shape is not exact")
    if publication._canonical_json(manifest) != manifest_bytes:
        raise ReleaseError("the publication manifest is not canonical JSON")
    if (
        manifest["schema"] != publication.PUBLICATION_SCHEMA
        or not isinstance(manifest["producer_repository"], str)
        or manifest["producer_repository"] != producer_repository
        or not isinstance(manifest["source_revision"], str)
        or manifest["source_revision"] != revision
        or not isinstance(manifest["verification_run_id"], int)
        or isinstance(manifest["verification_run_id"], bool)
        or manifest["verification_run_id"] != verification_run_id
        or not isinstance(manifest["bundle_workflow_run_id"], int)
        or isinstance(manifest["bundle_workflow_run_id"], bool)
        or manifest["bundle_workflow_run_id"] != bundle_workflow_run_id
        or not isinstance(manifest["release_tag"], str)
        or manifest["release_tag"] != f"proofbound-tools-{revision}"
    ):
        raise ReleaseError("the publication manifest identity differs")
    assets = manifest["assets"]
    if not isinstance(assets, list) or len(assets) != 5:
        raise ReleaseError("the publication payload inventory is not exact")
    expected_payload = set(_expected_names(revision)) - {
        publication.CHECKSUMS_NAME,
        publication.PUBLICATION_MANIFEST,
    }
    previous = ""
    observed: set[str] = set()
    for record in assets:
        if not isinstance(record, dict) or set(record) != {
            "name",
            "role",
            "sha256",
            "size_bytes",
        }:
            raise ReleaseError("a publication payload record is malformed")
        name = record["name"]
        digest = record["sha256"]
        size = record["size_bytes"]
        if (
            not isinstance(name, str)
            or name <= previous
            or name in observed
            or record["role"] != _role(name, revision)
            or not isinstance(digest, str)
            or DIGEST_PATTERN.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= publication.bundle.MAX_ARTIFACT_BYTES
        ):
            raise ReleaseError("a publication payload identity is invalid")
        data = publication._read_regular_file(
            staged / name,
            publication.bundle.MAX_ARCHIVE_BYTES
            if name.endswith(".tar.gz")
            else publication.MAX_SIDECAR_BYTES,
        )
        if digest != f"sha256:{hashlib.sha256(data).hexdigest()}" or size != len(data):
            raise ReleaseError(f"publication payload identity differs: {name}")
        observed.add(name)
        previous = name
    if observed != expected_payload:
        raise ReleaseError("the publication payload inventory is not exact")


def validate(
    release: object,
    staged: Path,
    revision: str,
    verification_run_id: int,
    bundle_workflow_run_id: int,
    producer_repository: str,
) -> None:
    """Require one published exact-revision release with the staged assets."""

    if publication.bundle.REVISION_PATTERN.fullmatch(revision) is None:
        raise ReleaseError("the source revision is not 40 lowercase hex characters")
    if verification_run_id < 1 or bundle_workflow_run_id < 1:
        raise ReleaseError("workflow run identities must be positive integers")
    if publication.REPOSITORY_PATTERN.fullmatch(producer_repository) is None:
        raise ReleaseError("the producer repository identity is invalid")
    if not isinstance(release, dict):
        raise ReleaseError("the release record is not an object")
    required = {"assets", "draft", "prerelease", "tag_name", "target_commitish"}
    if not required.issubset(release):
        raise ReleaseError("the release record omits required fields")
    expected_tag = f"proofbound-tools-{revision}"
    if (
        release["tag_name"] != expected_tag
        or release["target_commitish"] != revision
        or release["draft"] is not False
        or release["prerelease"] is not False
    ):
        raise ReleaseError("the hosted release identity or state differs")
    assets = release["assets"]
    if not isinstance(assets, list):
        raise ReleaseError("the hosted release asset inventory is invalid")
    if staged.is_symlink() or not staged.is_dir():
        raise ReleaseError("the staged publication directory is invalid")
    staged_names = tuple(sorted(path.name for path in staged.iterdir()))
    if staged_names != _expected_names(revision):
        raise ReleaseError("the staged publication asset inventory is not exact")
    checksums_data = publication._read_regular_file(
        staged / publication.CHECKSUMS_NAME, publication.MAX_SIDECAR_BYTES
    )
    checksums = publication._parse_checksums(checksums_data)
    if set(checksums) != set(staged_names) - {publication.CHECKSUMS_NAME}:
        raise ReleaseError("the publication checksum inventory is not exact")
    for name, digest in checksums.items():
        data = publication._read_regular_file(
            staged / name,
            publication.bundle.MAX_ARCHIVE_BYTES
            if name.endswith(".tar.gz")
            else publication.MAX_SIDECAR_BYTES,
        )
        if hashlib.sha256(data).hexdigest() != digest:
            raise ReleaseError(f"publication checksum differs: {name}")
    _validate_publication_manifest(
        staged,
        revision,
        verification_run_id,
        bundle_workflow_run_id,
        producer_repository,
    )
    observed: dict[str, dict[str, object]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ReleaseError("a hosted release asset is invalid")
        try:
            name = asset["name"]
            size = asset["size"]
            state = asset["state"]
            digest = asset["digest"]
        except KeyError as error:
            raise ReleaseError(
                "a hosted release asset omits identity fields"
            ) from error
        if (
            not isinstance(name, str)
            or name in observed
            or not isinstance(size, int)
            or isinstance(size, bool)
            or state != "uploaded"
            or not isinstance(digest, str)
            or DIGEST_PATTERN.fullmatch(digest) is None
        ):
            raise ReleaseError("a hosted release asset identity is invalid")
        observed[name] = asset
    if tuple(sorted(observed)) != staged_names:
        raise ReleaseError("the hosted release asset inventory is not exact")
    for name in staged_names:
        data = publication._read_regular_file(
            staged / name,
            publication.MAX_SIDECAR_BYTES
            if not name.endswith(".tar.gz")
            else publication.bundle.MAX_ARCHIVE_BYTES,
        )
        expected_digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if (
            observed[name]["size"] != len(data)
            or observed[name]["digest"] != expected_digest
        ):
            raise ReleaseError(f"hosted release asset identity differs: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-record", type=Path, required=True)
    parser.add_argument("--staged", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--verification-run-id", type=int, required=True)
    parser.add_argument("--bundle-workflow-run-id", type=int, required=True)
    parser.add_argument("--producer-repository", required=True)
    args = parser.parse_args()
    try:
        if publication.bundle.REVISION_PATTERN.fullmatch(args.revision) is None:
            raise ReleaseError("the source revision is not 40 lowercase hex characters")
        if args.verification_run_id < 1 or args.bundle_workflow_run_id < 1:
            raise ReleaseError("workflow run identities must be positive integers")
        if publication.REPOSITORY_PATTERN.fullmatch(args.producer_repository) is None:
            raise ReleaseError("the producer repository identity is invalid")
        validate(
            _load_json(args.release_record),
            args.staged.absolute(),
            args.revision,
            args.verification_run_id,
            args.bundle_workflow_run_id,
            args.producer_repository,
        )
    except (OSError, ReleaseError, publication.PublicationError) as error:
        print(f"tool bundle release rejected: {error}", file=sys.stderr)
        return 1
    print('{"accepted":true,"schema":"proofbound-tool-bundle-release-check/1"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
