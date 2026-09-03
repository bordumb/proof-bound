import pytest

from proofbound.windows_initialization_matrix import VARIANTS
from proofbound.windows_native_boundary import WindowsBoundaryOptions


def test_initialization_matrix_peels_one_boundary_at_a_time() -> None:
    assert [
        (name, options.active_process_limit, options.private_desktop)
        for name, options in VARIANTS
    ] == [
        ("registered", 1, True),
        ("broker-capacity", 2, True),
        ("kill-only", None, True),
        ("parent-station", None, False),
        ("visible-console", None, False),
    ]
    assert [options.create_no_window for _, options in VARIANTS] == [
        True,
        True,
        True,
        True,
        False,
    ]


def test_boundary_options_reject_nonpositive_process_limits() -> None:
    with pytest.raises(ValueError, match="positive or None"):
        WindowsBoundaryOptions(active_process_limit=0)
