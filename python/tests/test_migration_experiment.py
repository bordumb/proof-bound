from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from proofbound import migration_experiment

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT = ROOT / "docs/experiments/0017-mixed-language-migration"
CORPUS = EXPERIMENT / "corpus"


def _registered_runtimes_ready() -> bool:
    contract = json.loads((CORPUS / "contract.json").read_bytes())
    callers = {
        "python": EXPERIMENT / "subjects/python_caller.py",
        "typescript": EXPERIMENT / "subjects/typescript_caller.mjs",
    }
    for runtime in contract["runtimes"]:
        completed = subprocess.run(
            [
                runtime["program"],
                str(callers[runtime["language"]]),
                str(CORPUS / "contract.json"),
                str(CORPUS / "cases.json"),
                "baseline",
            ],
            check=False,
            capture_output=True,
            cwd=ROOT,
        )
        if completed.returncode != 0 or completed.stderr:
            return False
    return True


def test_source_line_counter_excludes_blanks_and_comments(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    source.write_text("# comment\n\nvalue = 1\n")
    assert migration_experiment._source_lines(source, "#") == 1


def test_experiment_requires_registered_repetition_count() -> None:
    with pytest.raises(ValueError, match="exactly ten repetitions"):
        migration_experiment.execute_experiment(
            ROOT,
            ROOT / "target/debug/proofbound-ir-prototype",
            repetitions=9,
        )


def test_retained_result_records_every_preregistered_success() -> None:
    retained = json.loads((EXPERIMENT / "results/execution.json").read_bytes())
    assert all(item["passed"] for item in retained["questions"].values())
    assert retained["metrics"]["foreign_calls"] == 48
    assert retained["metrics"]["exact_attack_rejections"] == 30
    assert retained["implementations"]["canonical_reports_equal"] is True


@pytest.mark.skipif(
    not _registered_runtimes_ready(), reason="requires the exact registered runtimes"
)
def test_retained_result_matches_fresh_execution() -> None:
    retained = json.loads((EXPERIMENT / "results/execution.json").read_bytes())
    fresh = migration_experiment.execute_experiment(
        ROOT, ROOT / "target/debug/proofbound-ir-prototype"
    )
    retained_elapsed = retained["metrics"].pop("elapsed_ms")
    fresh_elapsed = fresh["metrics"].pop("elapsed_ms")
    assert retained == fresh
    assert retained_elapsed <= 30_000
    assert fresh_elapsed <= 30_000
