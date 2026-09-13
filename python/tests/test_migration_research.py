from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from proofbound import migration_research

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT = ROOT / "docs/experiments/0017-mixed-language-migration"
CORPUS = EXPERIMENT / "corpus"


def _observations() -> list[dict[str, object]]:
    contract = json.loads((CORPUS / "contract.json").read_bytes())
    cases = json.loads((CORPUS / "cases.json").read_bytes())["cases"]
    observations = []
    for runtime in contract["runtimes"]:
        for phase in ("baseline", "migrated"):
            calls = []
            for case in cases:
                call = {
                    "schema": migration_research.CALL_SCHEMA,
                    "case_id": case["id"],
                    "phase": phase,
                    "language": runtime["language"],
                    "contract_identity": contract["identity"],
                    "artifact_identity": (
                        contract["artifact"]["identity"]
                        if phase == "migrated"
                        else None
                    ),
                    "operation": case["operation"],
                    "input_hex": case["input_hex"],
                    "input_value": case["input_value"],
                    **case["expected"],
                    "identity": "",
                }
                call["identity"] = migration_research.domain_hash(
                    migration_research.CALL_SCHEMA, call
                )
                calls.append(call)
            observation = {
                "schema": migration_research.OBSERVATIONS_SCHEMA,
                "language": runtime["language"],
                "phase": phase,
                "contract_identity": contract["identity"],
                "runtime": runtime,
                "calls": calls,
                "identity": "",
            }
            observation["identity"] = migration_research.domain_hash(
                migration_research.OBSERVATIONS_SCHEMA, observation
            )
            observations.append(observation)
    return observations


def test_independent_kernel_reconstructs_rust_report_exactly() -> None:
    subprocess.run(
        ["cargo", "build", "--locked", "--offline", "-p", "proofbound-ir-prototype"],
        check=True,
        cwd=ROOT,
    )
    envelope = migration_research.encode_observation_envelope(_observations())
    completed = subprocess.run(
        [
            str(ROOT / "target/debug/proofbound-ir-prototype"),
            "execute-migration",
            str(ROOT),
            str(CORPUS.relative_to(ROOT)),
            "/dev/stdin",
            "10",
        ],
        input=envelope,
        check=True,
        capture_output=True,
        cwd=ROOT,
    )
    assert completed.stderr == b""
    report = migration_research.validate_rust_report(
        ROOT, CORPUS.relative_to(ROOT), envelope, completed.stdout
    )
    assert len(report["attacks"]) == 30
    assert all(item["exact"] for item in report["attacks"])
    assert report["explanation"]["foreign_ceilings"] == [
        "claim:python-packet remains tested",
        "claim:typescript-packet remains tested",
    ]


def test_independent_kernel_rejects_noncanonical_envelope() -> None:
    with pytest.raises(migration_research.MigrationFailure, match="FB-NONCANONICAL"):
        migration_research.reconstruct_migration_report(
            ROOT,
            CORPUS.relative_to(ROOT),
            b'{"schema": "not-canonical"}',
        )
