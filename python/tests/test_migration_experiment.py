from __future__ import annotations

from pathlib import Path

import pytest

from proofbound import migration_experiment

ROOT = Path(__file__).resolve().parents[2]


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
