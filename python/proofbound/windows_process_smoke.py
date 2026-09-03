"""Exercise suspended AppContainer process creation for EXP-0023."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from proofbound.windows_enforcement_execute import canonical_json, domain_hash
from proofbound.windows_native_boundary import run_appcontainer_process


def main(argv: list[str] | None = None) -> int:
    """Run `whoami /all` inside the native boundary and retain its receipt."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: windows_process_smoke RECEIPT", file=sys.stderr)
        return 2
    executable = Path(os.environ["SystemRoot"]) / "System32" / "whoami.exe"
    try:
        result = run_appcontainer_process(
            [str(executable), "/all"],
            executable.parent,
            {
                "PB_REGISTERED_VALUE": "registered-env",
                "LOCALAPPDATA": os.environ["LOCALAPPDATA"],
                "SystemDrive": os.environ["SystemDrive"],
                "SystemRoot": os.environ["SystemRoot"],
                "TEMP": os.environ["TEMP"],
                "TMP": os.environ["TMP"],
            },
        )
        value = {
            "schema": "proofbound-research-windows-process-smoke/1",
            "experiment": "EXP-0023",
            "programme_experiment": "EXP-LANG-016",
            "command": [str(executable), "/all"],
            "result": result,
        }
        value["identity"] = domain_hash(
            "proofbound-research-windows-process-smoke/1", value
        )
        Path(arguments[0]).write_bytes(canonical_json(value))
        print(json.dumps({"exit_code": result["exit_code"], "receipt": arguments[0]}))
    except (OSError, TimeoutError, ValueError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
