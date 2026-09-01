#!/usr/bin/env python3
"""Synchronize product manifests from VERSION and delegate lock generation."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path


VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
)


class VersionError(ValueError):
    """A version source or derived declaration is malformed."""


def parse_version(value: str) -> str:
    value = value.strip()
    if VERSION_PATTERN.fullmatch(value) is None:
        raise VersionError(
            f"VERSION must contain one canonical X.Y.Z value, got {value!r}"
        )
    return value


def replace_toml_version(
    text: str, section: str | None, version: str, path: str
) -> str:
    lines = text.splitlines(keepends=True)
    active_section: str | None = None
    matches: list[int] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            active_section = stripped
            continue
        if active_section == section and re.fullmatch(r'version = "[^"]+"', stripped):
            matches.append(index)
    if len(matches) != 1:
        raise VersionError(
            f"{path} must contain exactly one version in {section or 'the root table'}"
        )
    index = matches[0]
    newline = "\n" if lines[index].endswith("\n") else ""
    lines[index] = f'version = "{version}"{newline}'
    return "".join(lines)


def workspace_package_names(root: Path) -> set[str]:
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    names: set[str] = set()
    for member in workspace["workspace"]["members"]:
        manifest = tomllib.loads(
            (root / member / "Cargo.toml").read_text(encoding="utf-8")
        )
        package = manifest["package"]
        if package.get("version") != {"workspace": True}:
            raise VersionError(
                f"{member}/Cargo.toml must inherit workspace.package.version"
            )
        names.add(package["name"])
    return names


def rendered_manifests(root: Path, version: str) -> dict[Path, str]:
    transforms = {
        root / "Cargo.toml": lambda text: replace_toml_version(
            text, "[workspace.package]", version, "Cargo.toml"
        ),
        root / "pyproject.toml": lambda text: replace_toml_version(
            text, "[project]", version, "pyproject.toml"
        ),
        root / "lakefile.toml": lambda text: replace_toml_version(
            text, None, version, "lakefile.toml"
        ),
    }
    return {
        path: transform(path.read_text(encoding="utf-8"))
        for path, transform in transforms.items()
    }


def synchronize_manifests(root: Path, version: str, check: bool) -> list[Path]:
    changed: list[Path] = []
    for path, rendered in rendered_manifests(root, version).items():
        current = path.read_text(encoding="utf-8")
        if current == rendered:
            continue
        changed.append(path)
        if not check:
            path.write_text(rendered, encoding="utf-8")
    return changed


def validate_lock_versions(root: Path, version: str) -> None:
    expected_packages = workspace_package_names(root)
    cargo_lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    cargo_versions = {
        package["name"]: package["version"]
        for package in cargo_lock["package"]
        if package["name"] in expected_packages and "source" not in package
    }
    missing = expected_packages - cargo_versions.keys()
    if missing:
        raise VersionError(
            f"Cargo.lock is missing workspace packages: {', '.join(sorted(missing))}"
        )
    drifted = sorted(name for name, declared in cargo_versions.items() if declared != version)
    if drifted:
        raise VersionError(
            f"Cargo.lock has stale workspace versions for: {', '.join(drifted)}"
        )

    uv_lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    editable = [
        package
        for package in uv_lock["package"]
        if package.get("name") == "proofbound"
        and package.get("source") == {"editable": "."}
    ]
    if len(editable) != 1 or editable[0].get("version") != version:
        raise VersionError("uv.lock has a stale or ambiguous editable proofbound version")


def refresh_lockfiles(root: Path) -> None:
    subprocess.run(["cargo", "update", "--workspace", "--offline"], cwd=root, check=True)
    subprocess.run(["uv", "lock"], cwd=root, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--check", action="store_true", help="fail if manifests or locks drift"
    )
    action.add_argument(
        "--sync", action="store_true", help="synchronize manifests and regenerate locks"
    )
    action.add_argument(
        "--set", metavar="X.Y.Z", help="write VERSION, synchronize, and regenerate locks"
    )
    parser.add_argument("--root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()

    root = (args.root or Path(__file__).resolve().parents[2]).resolve()
    try:
        if args.set is not None:
            version = parse_version(args.set)
        else:
            raw = (root / "VERSION").read_text(encoding="utf-8")
            if raw != raw.strip() + "\n":
                raise VersionError(
                    "VERSION must be a single value followed by one newline"
                )
            version = parse_version(raw)

        changed = synchronize_manifests(root, version, args.check)
        if args.check:
            if changed:
                for path in changed:
                    print(
                        f"version check failed: {path.relative_to(root)} is not {version}",
                        file=sys.stderr,
                    )
                print("run: python3 tools/ci/version.py --sync", file=sys.stderr)
                return 1
            validate_lock_versions(root, version)
            return 0

        if args.set is not None:
            (root / "VERSION").write_text(f"{version}\n", encoding="utf-8")
        for path in changed:
            print(f"updated {path.relative_to(root)} to {version}")
        print("refreshing Cargo.lock with cargo update --workspace")
        print("refreshing uv.lock with uv lock")
        refresh_lockfiles(root)
        validate_lock_versions(root, version)
        return 0
    except (
        KeyError,
        OSError,
        subprocess.CalledProcessError,
        tomllib.TOMLDecodeError,
        VersionError,
    ) as error:
        print(f"version check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
