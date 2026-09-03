from pathlib import Path
import zipfile

from proofbound.windows_python_closure_discovery import (
    build_standard_library_archive,
)


def test_standard_library_archive_is_deterministic_and_excludes_site_packages(
    tmp_path: Path,
) -> None:
    library = tmp_path / "Lib"
    (library / "encodings").mkdir(parents=True)
    (library / "site-packages").mkdir()
    (library / "encodings" / "utf_8.py").write_text("codec = 1\n", encoding="utf-8")
    (library / "os.py").write_text("name = 'nt'\n", encoding="utf-8")
    (library / "site-packages" / "untrusted.py").write_text(
        "loaded = True\n", encoding="utf-8"
    )
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    assert build_standard_library_archive(library, first) == 2
    assert build_standard_library_archive(library, second) == 2
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == ["encodings/utf_8.py", "os.py"]
