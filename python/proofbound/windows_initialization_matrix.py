"""Run the bounded non-evidentiary EXP-0025 initialization matrix."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any

from proofbound.windows_enforcement_execute import canonical_json, domain_hash
from proofbound.windows_native_boundary import (
    WindowsBoundaryOptions,
    run_appcontainer_process,
)


SCHEMA = "proofbound-research-windows-initialization-matrix/1"
VARIANTS = [
    ("registered", WindowsBoundaryOptions()),
    ("broker-capacity", WindowsBoundaryOptions(active_process_limit=2)),
    ("kill-only", WindowsBoundaryOptions(active_process_limit=None)),
    (
        "parent-station",
        WindowsBoundaryOptions(active_process_limit=None, private_desktop=False),
    ),
    (
        "visible-console",
        WindowsBoundaryOptions(
            active_process_limit=None,
            private_desktop=False,
            create_no_window=False,
        ),
    ),
]


def _option_value(options: WindowsBoundaryOptions) -> dict[str, Any]:
    return {
        "active_process_limit": options.active_process_limit,
        "private_desktop": options.private_desktop,
        "create_no_window": options.create_no_window,
    }


def capture() -> dict[str, Any]:
    """Execute the fixed discovery variants without producing evidence."""

    executable = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
    command = [str(executable), "/d", "/c", "exit", "0"]
    variants = []
    for variant_id, options in VARIANTS:
        value: dict[str, Any] = {
            "id": variant_id,
            "options": _option_value(options),
        }
        try:
            result = run_appcontainer_process(
                command,
                executable.parent,
                {
                    "PB_REGISTERED_VALUE": "registered-env",
                    "SystemDrive": os.environ["SystemDrive"],
                    "SystemRoot": os.environ["SystemRoot"],
                },
                stage_application=True,
                options=options,
            )
            value["result"] = result
            value["entered"] = result["exit_code"] == 0
        except (OSError, TimeoutError, ValueError) as issue:
            value["error"] = {
                "type": type(issue).__name__,
                "message": str(issue),
            }
            value["entered"] = False
        variants.append(value)
    result = {
        "schema": SCHEMA,
        "experiment": "EXP-0025",
        "programme_experiment": "EXP-LANG-018",
        "diagnostic_only": True,
        "reusable_evidence": False,
        "command": command,
        "variants": variants,
    }
    result["identity"] = domain_hash(SCHEMA, result)
    return result


def main(argv: list[str] | None = None) -> int:
    """Write the initialization matrix result."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: windows_initialization_matrix OUTPUT", file=sys.stderr)
        return 2
    value = capture()
    Path(arguments[0]).write_bytes(canonical_json(value))
    print(
        json.dumps(
            [
                {
                    "id": variant["id"],
                    "entered": variant["entered"],
                    "exit_code": variant.get("result", {}).get("exit_code"),
                    "error": variant.get("error"),
                }
                for variant in value["variants"]
            ],
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
