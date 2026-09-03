from pathlib import Path

from proofbound.windows_runtime_entry_matrix import EXPECTED_OUTPUTS, _commands


def test_runtime_entry_commands_are_exact(monkeypatch) -> None:
    monkeypatch.setattr(
        "proofbound.windows_runtime_entry_matrix.shutil.which",
        lambda name: r"C:\toolchain\node.exe" if name == "node" else None,
    )
    monkeypatch.setattr(
        "proofbound.windows_runtime_entry_matrix.sys.executable",
        r"C:\toolchain\python.exe",
    )

    assert _commands(Path(r"C:\state\runtime_smoke.exe")) == {
        "python": [r"C:\toolchain\python.exe", "-c", "print('python-entry')"],
        "node": [
            r"C:\toolchain\node.exe",
            "-e",
            "console.log('node-entry')",
        ],
        "rust": [r"C:\state\runtime_smoke.exe"],
    }
    assert EXPECTED_OUTPUTS == {
        "python": "python-entry\n",
        "node": "node-entry\n",
        "rust": "rust-entry\n",
    }
