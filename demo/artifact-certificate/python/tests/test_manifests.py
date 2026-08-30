from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

import pytest

from artifact_certificate.manifests import (
    ManifestError,
    validate_document,
    validate_tree,
)

ROOT = Path(__file__).resolve().parents[2]


def test_committed_manifests_are_strict_and_cross_linked() -> None:
    validate_tree(ROOT)


def test_unknown_claim_field_fails_closed() -> None:
    path = ROOT / "claims/PBAC-SUM-001.toml"
    with path.open("rb") as source:
        document = tomllib.load(source)
    document["optimistic_status"] = "PROVED"
    with pytest.raises(ManifestError, match="PBAC_M_UNKNOWN_FIELD"):
        validate_document("claim", document, path)


def test_generator_outputs_are_an_exact_literal_inventory() -> None:
    path = ROOT / "evidence/pbac-fixture-generation.toml"
    with path.open("rb") as source:
        document = tomllib.load(source)
    document["outputs"] = document["outputs"][:-1]
    with pytest.raises(ManifestError, match="PBAC_M_GENERATOR_BOUNDARY"):
        validate_document("evidence", document, path)


def test_omitted_assumption_cannot_upgrade_axiomatized_claim(tmp_path: Path) -> None:
    mutated = tmp_path / "artifact-certificate"
    shutil.copytree(ROOT, mutated)
    path = mutated / "claims/PBAC-CALIBRATED-001.toml"
    source = path.read_text()
    path.write_text(
        source.replace(
            'assumptions = ["PBAC-CALIBRATION-AX-001"]',
            "assumptions = []",
        )
    )
    with pytest.raises(ManifestError, match="PBAC_M_ASSUMPTION_DRIFT"):
        validate_tree(mutated)
