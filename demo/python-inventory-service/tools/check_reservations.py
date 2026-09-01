"""Independent arithmetic checker for the registered reservation vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _accepted(capacity: int, committed: int, requested: int) -> tuple[bool, int]:
    if min(capacity, committed, requested) < 0 or committed > capacity:
        raise ValueError("invalid vector state")
    accepted = requested <= capacity - committed
    return accepted, committed + requested if accepted else committed


def main(path: str) -> int:
    """Validate the independent vector inventory and emit the checker ABI."""

    document: dict[str, Any] = json.loads(Path(path).read_bytes())
    if set(document) != {"schema", "vectors"} or document["schema"] != (
        "proofbound-python-inventory-vectors/1"
    ):
        return 2
    for vector in document["vectors"]:
        accepted, result = _accepted(
            vector["capacity"], vector["committed"], vector["requested"]
        )
        if accepted != vector["accepted"] or result != vector["result"]:
            return 2
        if result > vector["capacity"]:
            return 2
    report = {
        "accepted": True,
        "inventory": ["reservation-vectors"],
        "schema": "proofbound-independent-check-result/1",
    }
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
