from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_windows_portable import filter_qt_gui_binaries


def test_qt_packaging_keeps_only_qt_owned_icu() -> None:
    binaries = [
        ("icuuc.dll", r"C:\tools\poppler\Library\bin\icuuc.dll"),
        (
            r"PySide6\icuuc.dll",
            r"C:\python\Lib\site-packages\PySide6\icuuc.dll",
        ),
        ("icuuc.dll", r"C:\Windows\System32\icuuc.dll"),
    ]

    assert filter_qt_gui_binaries(binaries) == (binaries[1],)


def test_integrations_preview_spec_filters_analysis_binaries() -> None:
    spec = (
        PROJECT_ROOT / "packaging/windows/AgentGuardianIntegrationsPreview.spec"
    ).read_text(encoding="utf-8")

    assert "binaries = list(filter_qt_gui_binaries(a.binaries))" in spec
