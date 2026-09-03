"""Probe EXP-0025 runtime entry under the isolated Windows boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from proofbound.windows_enforcement_execute import canonical_json, domain_hash
from proofbound.windows_native_boundary import (
    WindowsBoundaryOptions,
    run_appcontainer_process,
)


SCHEMA = "proofbound-research-windows-runtime-entry-matrix/1"
EXPECTED_OUTPUTS = {
    "python": "python-entry\n",
    "node": "node-entry\n",
    "rust": "rust-entry\n",
}


def _commands(rust_binary: Path) -> dict[str, list[str]]:
    node = shutil.which("node")
    if node is None:
        raise OSError("node is unavailable")
    return {
        "python": [sys.executable, "-c", "print('python-entry')"],
        "node": [node, "-e", "console.log('node-entry')"],
        "rust": [str(rust_binary)],
    }


def capture() -> dict[str, Any]:
    """Run direct and executable-only staged entry for three runtimes."""

    options = WindowsBoundaryOptions(create_no_window=False)
    environment = {
        "PB_REGISTERED_VALUE": "registered-env",
        "SystemDrive": os.environ["SystemDrive"],
        "SystemRoot": os.environ["SystemRoot"],
    }
    rows = []
    with tempfile.TemporaryDirectory(prefix="proofbound-exp0025-") as temporary:
        root = Path(temporary)
        source = root / "runtime_smoke.rs"
        binary = root / "runtime_smoke.exe"
        source.write_text('fn main() { println!("rust-entry"); }\n', encoding="utf-8")
        subprocess.run(
            ["rustc", "--edition", "2021", str(source), "-o", str(binary)],
            check=True,
            capture_output=True,
        )
        for runtime, command in _commands(binary).items():
            for staged in (False, True):
                row: dict[str, Any] = {
                    "runtime": runtime,
                    "staged_executable_only": staged,
                    "command": command,
                }
                try:
                    result = run_appcontainer_process(
                        command,
                        Path(command[0]).parent,
                        environment,
                        stage_application=staged,
                        options=options,
                    )
                    row["result"] = result
                    row["entered"] = (
                        result["exit_code"] == 0
                        and result["stdout"] == EXPECTED_OUTPUTS[runtime]
                        and result["stderr"] == ""
                    )
                except (OSError, TimeoutError, ValueError) as issue:
                    row["error"] = {
                        "type": type(issue).__name__,
                        "message": str(issue),
                    }
                    row["entered"] = False
                rows.append(row)
    value = {
        "schema": SCHEMA,
        "experiment": "EXP-0025",
        "programme_experiment": "EXP-LANG-018",
        "diagnostic_only": True,
        "reusable_evidence": False,
        "boundary": {
            "active_process_limit": options.active_process_limit,
            "private_desktop": options.private_desktop,
            "create_no_window": options.create_no_window,
        },
        "rows": rows,
    }
    value["identity"] = domain_hash(SCHEMA, value)
    return value


def main(argv: list[str] | None = None) -> int:
    """Write the bounded runtime-entry matrix."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: windows_runtime_entry_matrix OUTPUT", file=sys.stderr)
        return 2
    value = capture()
    Path(arguments[0]).write_bytes(canonical_json(value))
    print(
        json.dumps(
            [
                {
                    "runtime": row["runtime"],
                    "staged": row["staged_executable_only"],
                    "entered": row["entered"],
                    "exit_code": row.get("result", {}).get("exit_code"),
                    "error": row.get("error"),
                }
                for row in value["rows"]
            ],
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
