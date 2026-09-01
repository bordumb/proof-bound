#!/usr/bin/env python3
"""Synchronize and validate Proofbound's product version declarations."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


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


def replace_specification_version(text: str, version: str) -> str:
    rendered, count = re.subn(
        r"(?m)^\*\*Version:\*\* [^\n]+$",
        f"**Version:** {version}",
        text,
        count=1,
    )
    if count != 1:
        raise VersionError(
            "docs/specs/0001_initial_spec.md must contain one Version header"
        )
    return rendered


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


def replace_lock_package_versions(
    text: str, package_names: set[str], version: str, path: str
) -> str:
    prefix, *blocks = text.split("[[package]]")
    found: set[str] = set()
    rendered = [prefix]
    for block in blocks:
        parsed = tomllib.loads("[[package]]" + block)["package"][0]
        name = parsed["name"]
        if name in package_names:
            if "source" in parsed:
                raise VersionError(
                    f"{path} workspace package {name} unexpectedly has a source"
                )
            block, count = re.subn(
                r'(?m)^version = "[^"]+"$',
                f'version = "{version}"',
                block,
                count=1,
            )
            if count != 1:
                raise VersionError(f"{path} package {name} has no unique version")
            found.add(name)
        rendered.extend(("[[package]]", block))
    missing = package_names - found
    if missing:
        raise VersionError(
            f"{path} is missing workspace packages: {', '.join(sorted(missing))}"
        )
    return "".join(rendered)


def replace_uv_version(text: str, version: str) -> str:
    prefix, *blocks = text.split("[[package]]")
    rendered = [prefix]
    matches = 0
    for block in blocks:
        parsed = tomllib.loads("[[package]]" + block)["package"][0]
        if parsed.get("name") == "proofbound" and parsed.get("source") == {
            "editable": "."
        }:
            block, count = re.subn(
                r'(?m)^version = "[^"]+"$',
                f'version = "{version}"',
                block,
                count=1,
            )
            if count != 1:
                raise VersionError(
                    "uv.lock editable proofbound package has no unique version"
                )
            matches += 1
        rendered.extend(("[[package]]", block))
    if matches != 1:
        raise VersionError(
            "uv.lock must contain exactly one editable proofbound package"
        )
    return "".join(rendered)


def rendered_files(root: Path, version: str) -> dict[Path, str]:
    cargo_names = workspace_package_names(root)
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
        root / "Cargo.lock": lambda text: replace_lock_package_versions(
            text, cargo_names, version, "Cargo.lock"
        ),
        root / "uv.lock": lambda text: replace_uv_version(text, version),
        root
        / "docs/specs/0001_initial_spec.md": lambda text: replace_specification_version(
            text, version
        ),
    }
    return {
        path: transform(path.read_text(encoding="utf-8"))
        for path, transform in transforms.items()
    }


def synchronize(root: Path, version: str, check: bool) -> list[Path]:
    changed: list[Path] = []
    for path, rendered in rendered_files(root, version).items():
        current = path.read_text(encoding="utf-8")
        if current == rendered:
            continue
        changed.append(path)
        if not check:
            path.write_text(rendered, encoding="utf-8")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--check", action="store_true", help="fail if derived versions drift"
    )
    action.add_argument("--sync", action="store_true", help="synchronize from VERSION")
    action.add_argument("--set", metavar="X.Y.Z", help="write VERSION and synchronize")
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
        changed = synchronize(root, version, args.check)
        if args.set is not None:
            (root / "VERSION").write_text(f"{version}\n", encoding="utf-8")
    except (KeyError, OSError, tomllib.TOMLDecodeError, VersionError) as error:
        print(f"version check failed: {error}", file=sys.stderr)
        return 1

    if args.check and changed:
        for path in changed:
            print(
                f"version check failed: {path.relative_to(root)} is not {version}",
                file=sys.stderr,
            )
        print("run: python3 tools/ci/version.py --sync", file=sys.stderr)
        return 1
    if not args.check:
        for path in changed:
            print(f"updated {path.relative_to(root)} to {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
