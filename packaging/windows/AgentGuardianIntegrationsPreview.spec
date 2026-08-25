# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


project_root = Path(__file__).resolve().parents[2]
source_root = project_root / "src"
package_root = source_root / "agentguardian"
skill_root = project_root / "skills/agentguardian"

datas = [
    *[(str(path), "agentguardian") for path in sorted(package_root.glob("*.py"))],
    (str(package_root / "source_policy.json"), "agentguardian"),
    (str(project_root / "rules" / "default.json"), "agentguardian/rules"),
    (str(skill_root / "LICENSE"), "agentguardian_skill"),
    (str(skill_root / "README.md"), "agentguardian_skill"),
    (str(skill_root / "SKILL.md"), "agentguardian_skill"),
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

pyz = PYZ(a.pure)

gui = EXE(
    pyz,
    a.scripts,
    a.binaries,
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
)

mcp = EXE(
    pyz,
    a.scripts,
    a.binaries,
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
    a.binaries,
    a.datas,
    a.zipfiles,
    strip=False,
    upx=False,
    name='AgentGuardian',
)
