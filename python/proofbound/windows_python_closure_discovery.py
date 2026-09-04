"""Construct and probe the bounded EXP-0025 CPython runtime closure."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any
import zipfile

from proofbound.windows_enforcement_execute import canonical_json, domain_hash
from proofbound.windows_native_boundary import (
    WindowsBoundaryOptions,
    run_appcontainer_process,
)


SCHEMA = "proofbound-research-windows-python-initialization-closure/1"
MAX_STAGED_FILES = 512


def build_standard_library_archive(library: Path, destination: Path) -> int:
    """Create a deterministic archive of the pure-Python standard library."""

    sources = sorted(
        path
        for path in library.rglob("*.py")
        if "site-packages" not in {part.casefold() for part in path.parts}
    )
    if not sources:
        raise ValueError("the Python standard-library inventory is empty")
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for source in sources:
            relative = source.relative_to(library).as_posix()
            entry = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, source.read_bytes())
    return len(sources)


def native_runtime_files(root: Path) -> tuple[tuple[Path, str], ...]:
    """Return the canonical staged native CPython file inventory."""

    rows = [(path, path.name) for path in sorted(root.glob("*.dll"))]
    dlls = root / "DLLs"
    if dlls.is_dir():
        rows.extend(
            (path, f"DLLs/{path.name}")
            for path in sorted(dlls.iterdir())
            if path.suffix.casefold() in {".dll", ".pyd"}
        )
    return tuple(rows)


def capture() -> dict[str, Any]:
    """Run Python from an exact staged native and standard-library closure."""

    runtime_root = Path(sys.executable).parent
    library = runtime_root / "Lib"
    archive_name = f"python{sys.version_info.major}{sys.version_info.minor}.zip"
    with tempfile.TemporaryDirectory(prefix="proofbound-exp0025-python-") as temporary:
        archive = Path(temporary) / archive_name
        module_count = build_standard_library_archive(library, archive)
        staged = (*native_runtime_files(runtime_root), (archive, archive_name))
        if len(staged) > MAX_STAGED_FILES:
            raise ValueError("the Python native closure exceeds its registered bound")
        application = "{APPLICATION_ROOT}"
        separator = ";"
        environment = {
            "PB_REGISTERED_VALUE": "registered-env",
            "SystemDrive": os.environ["SystemDrive"],
            "SystemRoot": os.environ["SystemRoot"],
            "PYTHONHOME": application,
            "PYTHONPATH": separator.join(
                [f"{application}/{archive_name}", f"{application}/DLLs"]
            ),
        }
        result = run_appcontainer_process(
            [sys.executable, "-S", "-c", "print('python-closure-entry')"],
            runtime_root,
            environment,
            stage_application=True,
            staged_files=staged,
            options=WindowsBoundaryOptions(create_no_window=False),
        )
    value = {
        "schema": SCHEMA,
        "experiment": "EXP-0025",
        "programme_experiment": "EXP-LANG-018",
        "diagnostic_only": True,
        "reusable_evidence": False,
        "runtime_root": str(runtime_root),
        "pure_python_modules": module_count,
        "native_files": len(staged) - 1,
        "result": result,
        "entered": (
            result["exit_code"] == 0
            and result["stdout"] == "python-closure-entry\n"
            and result["stderr"] == ""
        ),
    }
    value["identity"] = domain_hash(SCHEMA, value)
    return value


def main(argv: list[str] | None = None) -> int:
    """Write the CPython closure discovery result."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: windows_python_closure_discovery OUTPUT", file=sys.stderr)
        return 2
    value = capture()
    Path(arguments[0]).write_bytes(canonical_json(value))
    print(
        json.dumps(
            {
                "entered": value["entered"],
                "exit_code": value["result"]["exit_code"],
                "native_files": value["native_files"],
                "pure_python_modules": value["pure_python_modules"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
