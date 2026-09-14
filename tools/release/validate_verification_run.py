#!/usr/bin/env python3
"""Validate the exact mainline Proofbound verification run for a tool bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


VERIFY_WORKFLOW_PATH = ".github/workflows/ci.yml"
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")


class VerificationRunError(ValueError):
    """One fail-closed verification-run identity error."""


def _read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise VerificationRunError(f"cannot parse GitHub record: {path}") from error
    if not isinstance(value, dict):
        raise VerificationRunError(f"GitHub record is not an object: {path}")
    return value


def validate(
    run: dict[str, object], workflow: dict[str, object], revision: str
) -> None:
    """Require one successful push run of the exact Verify workflow and revision."""

    if REVISION_PATTERN.fullmatch(revision) is None:
        raise VerificationRunError("the requested source revision is invalid")
    workflow_id = workflow.get("id")
    if (
        not isinstance(workflow_id, int)
        or isinstance(workflow_id, bool)
        or workflow_id < 1
        or workflow.get("path") != VERIFY_WORKFLOW_PATH
    ):
        raise VerificationRunError("the authoritative Verify workflow is invalid")
    expected = {
        "workflow_id": workflow_id,
        "path": VERIFY_WORKFLOW_PATH,
        "event": "push",
        "head_branch": "main",
        "head_sha": revision,
        "status": "completed",
        "conclusion": "success",
    }
    if any(run.get(name) != value for name, value in expected.items()):
        raise VerificationRunError(
            "the run is not the exact successful mainline Verify workflow run"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-record", type=Path, required=True)
    parser.add_argument("--workflow-record", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    try:
        validate(
            _read_json(args.run_record),
            _read_json(args.workflow_record),
            args.revision,
        )
    except VerificationRunError as error:
        print(f"verification run rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
