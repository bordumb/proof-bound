"""Extract the EXP-0025 process tree from a retained Process Monitor log."""

from __future__ import annotations

import importlib
import json
from pathlib import Path, PureWindowsPath
import sys
from typing import Any, Protocol

from proofbound.windows_enforcement_execute import (
    canonical_json,
    domain_hash,
    sha256_bytes,
)


SCHEMA = "proofbound-research-windows-initialization-process-tree/1"
MAX_PROCESSES = 64
MAX_MODULES_PER_PROCESS = 512


class ModuleRecord(Protocol):
    """Required Process Monitor module fields."""

    path: str
    size: int
    version: str
    company: str
    description: str
    timestamp: int


class ProcessRecord(Protocol):
    """Required Process Monitor process fields."""

    pid: int
    parent_pid: int
    process_name: str
    image_path: str
    command_line: str
    integrity: str
    user: str
    start_time: int
    end_time: int
    modules: list[ModuleRecord]


def _windows_path(value: str) -> str:
    """Return a case-insensitive canonical comparison form."""

    return str(PureWindowsPath(value)).casefold()


def select_process_tree(
    processes: list[ProcessRecord], executed_image: str
) -> list[ProcessRecord]:
    """Select exactly one executed image and all of its descendants."""

    roots = [
        process
        for process in processes
        if _windows_path(process.image_path) == _windows_path(executed_image)
    ]
    if len(roots) != 1:
        raise ValueError(f"expected one executed image in PML, found {len(roots)}")
    selected = {roots[0].pid}
    changed = True
    while changed:
        changed = False
        for process in processes:
            if process.parent_pid in selected and process.pid not in selected:
                selected.add(process.pid)
                changed = True
    result = sorted(
        (process for process in processes if process.pid in selected),
        key=lambda process: (process.start_time, process.pid),
    )
    if len(result) > MAX_PROCESSES:
        raise ValueError("selected process tree exceeds its registered bound")
    return result


def _module(module: ModuleRecord) -> dict[str, Any]:
    return {
        "path": module.path,
        "size_bytes": module.size,
        "version": module.version,
        "company": module.company,
        "description": module.description,
        "timestamp": module.timestamp,
    }


def _process(process: ProcessRecord) -> dict[str, Any]:
    if len(process.modules) > MAX_MODULES_PER_PROCESS:
        raise ValueError("process module inventory exceeds its registered bound")
    return {
        "pid": process.pid,
        "parent_pid": process.parent_pid,
        "process_name": process.process_name,
        "image_path": process.image_path,
        "command_line": process.command_line,
        "integrity": process.integrity,
        "user": process.user,
        "start_time": process.start_time,
        "end_time": process.end_time,
        "modules": [_module(module) for module in process.modules],
    }


def main(argv: list[str] | None = None) -> int:
    """Write a bounded process-tree extract from one retained PML trace."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: windows_procmon_discovery PML SMOKE_RECEIPT OUTPUT", file=sys.stderr
        )
        return 2
    pml_path, smoke_path, output_path = map(Path, arguments)
    smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
    executed_image = smoke["result"]["executed_command"][0]
    parser = importlib.import_module("procmon_parser")
    with pml_path.open("rb") as stream:
        reader = parser.ProcmonLogsReader(
            stream, should_get_stacktrace=False, should_get_details=False
        )
        processes = select_process_tree(reader.processes(), executed_image)
        system = reader.system_details()
    value = {
        "schema": SCHEMA,
        "experiment": "EXP-0025",
        "programme_experiment": "EXP-LANG-018",
        "diagnostic_only": True,
        "reusable_evidence": False,
        "pml_sha256": sha256_bytes(pml_path.read_bytes()),
        "executed_image": executed_image,
        "system": system,
        "processes": [_process(process) for process in processes],
    }
    value["identity"] = domain_hash(SCHEMA, value)
    Path(output_path).write_bytes(canonical_json(value))
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
