from pathlib import Path

from proofbound import windows_wfp_attacks as attacks
from proofbound import windows_wfp_research as research


ROOT = Path(__file__).resolve().parents[2]


def test_registered_attack_inventory_is_exact() -> None:
    assert len(attacks.MUTATIONS) == len(research.ATTACKS) == 48
    assert [attack_id for attack_id, _ in research.ATTACKS[38:]] == [
        f"EXP-0027-A{index:03d}" for index in range(39, 49)
    ]


def test_observer_source_excludes_policy_mutation_apis() -> None:
    source = (ROOT / research.OBSERVER_SOURCE).read_text(encoding="utf-8")
    assert "FwpmEngineSetOption" not in source
    assert "FwpmFilterAdd" not in source
    assert "FwpmFilterDelete" not in source
    assert "NetworkIsolationSetAppContainerConfig" not in source
