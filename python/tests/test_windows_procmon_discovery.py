from types import SimpleNamespace

import pytest

from proofbound.windows_procmon_discovery import select_process_tree


def process(pid: int, parent_pid: int, image_path: str) -> SimpleNamespace:
    return SimpleNamespace(
        pid=pid,
        parent_pid=parent_pid,
        image_path=image_path,
        start_time=pid,
    )


def test_select_process_tree_includes_transitive_descendants() -> None:
    records = [
        process(4, 0, r"C:\Windows\System32\unrelated.exe"),
        process(12, 8, r"C:\sandbox\CMD.EXE"),
        process(13, 12, r"C:\Windows\System32\conhost.exe"),
        process(14, 13, r"C:\Windows\System32\broker.exe"),
    ]

    selected = select_process_tree(records, r"c:\sandbox\cmd.exe")

    assert [record.pid for record in selected] == [12, 13, 14]


@pytest.mark.parametrize("count", [0, 2])
def test_select_process_tree_requires_one_exact_root(count: int) -> None:
    records = [process(index + 1, 0, r"C:\sandbox\cmd.exe") for index in range(count)]

    with pytest.raises(ValueError, match=f"found {count}"):
        select_process_tree(records, r"C:\sandbox\cmd.exe")
