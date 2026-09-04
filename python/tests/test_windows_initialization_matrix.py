import pytest

from proofbound.windows_initialization_matrix import VARIANTS
from proofbound.windows_native_boundary import (
    WindowsBoundaryOptions,
    _safe_staged_path,
    _validate_disjoint_paths,
)


def test_initialization_matrix_peels_one_boundary_at_a_time() -> None:
    assert [
        (name, options.active_process_limit, options.private_desktop)
        for name, options in VARIANTS
    ] == [
        ("registered", 1, True),
        ("broker-capacity", 2, True),
        ("kill-only", None, True),
        ("parent-station", None, False),
        ("private-console-kill-only", None, True),
        ("private-console-broker-capacity", 2, True),
        ("private-console-registered-job", 1, True),
        ("parent-console", None, False),
    ]
    assert [options.create_no_window for _, options in VARIANTS] == [
        True,
        True,
        True,
        True,
        False,
        False,
        False,
        False,
    ]


def test_boundary_options_reject_nonpositive_process_limits() -> None:
    with pytest.raises(ValueError, match="positive or None"):
        WindowsBoundaryOptions(active_process_limit=0)


def test_boundary_options_require_canonical_drive_alias() -> None:
    assert WindowsBoundaryOptions(drive_alias="P:").drive_alias == "P:"
    for value in ("p:", "P", "P:/", "PP:"):
        with pytest.raises(ValueError, match="uppercase drive letter"):
            WindowsBoundaryOptions(drive_alias=value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "/absolute",
        "../escape",
        "nested/../escape",
        "./relative",
        "double//separator",
        "trailing/",
        "back\\slash",
        "drive:C",
        "white space",
        "line\nbreak",
        "non-ascii-é",
    ],
)
def test_staged_paths_reject_ambiguous_or_unsafe_values(value: str) -> None:
    with pytest.raises(ValueError, match="staged path"):
        _safe_staged_path(value)


def test_staged_paths_accept_canonical_portable_values() -> None:
    assert _safe_staged_path("DLLs/_socket.pyd").as_posix() == "DLLs/_socket.pyd"


def test_staged_paths_are_case_insensitively_prefix_disjoint() -> None:
    with pytest.raises(ValueError, match="prefix-disjoint"):
        _validate_disjoint_paths(
            [_safe_staged_path("Runtime"), _safe_staged_path("runtime/file.dll")],
            "staged files",
        )
