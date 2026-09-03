"""Exercise suspended AppContainer process creation for EXP-0023."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from proofbound.windows_enforcement_execute import canonical_json, domain_hash
from proofbound.windows_native_boundary import run_appcontainer_process


def main(argv: list[str] | None = None) -> int:
    """Run a no-op inside the native boundary and retain its token receipt."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: windows_process_smoke RECEIPT", file=sys.stderr)
        return 2
    executable = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
    command = [str(executable), "/d", "/c", "exit", "0"]
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
        )
        token_verified = (
            result["exit_code"] == 0
            and result["child_token"]["verified_before_resume"]
            and result["child_token"]["appcontainer_sid"] == result["appcontainer_sid"]
            and result["child_token"]["integrity_sid"] == "S-1-16-4096"
            and result["child_token"]["administrator_deny_only"]
        )
        value = {
            "schema": "proofbound-research-windows-process-smoke/1",
            "experiment": "EXP-0023",
            "programme_experiment": "EXP-LANG-016",
            "command": command,
            "result": result,
            "token_verified": token_verified,
        }
        value["identity"] = domain_hash(
            "proofbound-research-windows-process-smoke/1", value
        )
        Path(arguments[0]).write_bytes(canonical_json(value))
        print(
            json.dumps(
                {
                    "exit_code": result["exit_code"],
                    "receipt": arguments[0],
                    "token_verified": token_verified,
                }
            )
        )
        if not token_verified:
            return 1
    except (OSError, TimeoutError, ValueError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
