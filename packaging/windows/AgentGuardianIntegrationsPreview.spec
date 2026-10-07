# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import sys


# PyInstaller executes spec files without defining __file__.
project_root = Path(SPECPATH).resolve().parents[1]
sys.path.insert(0, str(project_root))
from scripts.build_windows_portable import filter_qt_gui_binaries

source_root = project_root / "src"
package_root = source_root / "agentguardian"
datas = [
    *[(str(path), "agentguardian") for path in sorted(package_root.glob("*.py"))],
    (str(package_root / "source_policy.json"), "agentguardian"),
    (str(project_root / "rules" / "default.json"), "agentguardian/rules"),
    *[(str(path), "agentguardian/assets") for path in sorted((package_root / "assets").glob("*"))],
]

a = Analysis(
    [str(package_root / "__main__.py")],
    pathex=[str(source_root)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[str(project_root / "scripts" / "pyinstaller_hooks")],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PySide6.QtNetwork"],
    noarchive=False,
)
binaries = list(filter_qt_gui_binaries(a.binaries))

pyz = PYZ(a.pure)

gui = EXE(
    pyz,
    a.scripts,
    binaries,
    a.datas,
    [],
    name='AgentGuardian',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    exclude_binaries=True,
    icon=str(package_root / "assets" / "agentguardian.ico"),
)

mcp = EXE(
    pyz,
    a.scripts,
    binaries,
    a.datas,
    [],
    name='AgentGuardianMcp',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    exclude_binaries=True,
)

COLLECT(
    gui,
    mcp,
    binaries,
    a.datas,
    a.zipfiles,
    strip=False,
    upx=False,
    name='AgentGuardian',
)
