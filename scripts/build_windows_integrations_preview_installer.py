"""Build and verify the unsigned 0.3 integrations-preview installer."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.build_windows_portable import (
    _require_current_source_identity,
    canonical_json_bytes,
    require_profile_snapshot_unchanged,
    validate_build_time,
    validate_git_build_context,
)
from scripts.verify_integrations_preview_profile import (
    ProfileSnapshot,
    load_profile_snapshot,
    verify_profile_evidence,
    verify_payload,
    verify_profile,
)


DISPLAY_VERSION = "0.3.0-preview.1"
FILE_VERSION = "0.3.0.1"
APP_ID = "{A64DBF23-FE14-4E04-89AE-0924666A03DE}"
INSTALLER_NAME = "AgentGuardian-Setup-0.3.0-preview.1-x64.exe"
INSTALL_DIRECTORY = r"{localappdata}\Programs\AgentGuardian Integrations Preview"
GUI_LAUNCHER = "AgentGuardian.exe"
MCP_LAUNCHER = "AgentGuardianMcp.exe"
COMPILER_VERSION = "7.0.2"
COMPILER_SHA256 = "0ff6140d641f84b64204a2c4d52207c6fc437c9f4db8779c83083d84f7e3d70d"
PROFILE_NAME = "integrations_preview"
PROFILE_RELATIVE = Path("release_profiles/integrations_preview.json")
SCRIPT_RELATIVE = Path("packaging/windows/AgentGuardianIntegrationsPreview.iss")
INSTALLER_SCRIPT_SHA256 = "ca616949f3e81cf9267b1a2879d31d213f0728716328ab28660768f52d2d03af"
MAX_FILE_BYTES = 16 * 1024 * 1024


def build_iscc_command(
    *,
    iscc: Path,
    script: Path,
    bundle_root: Path,
    output_root: Path,
    source_commit: str,
    built_at: str,
) -> tuple[str, ...]:
    paths = (iscc, script, bundle_root, output_root)
    if any(not path.is_absolute() for path in paths):
        raise ValueError("compiler paths must be absolute")
    if len(source_commit) != 40 or any(c not in "0123456789abcdef" for c in source_commit):
        raise ValueError("source commit must be a full lowercase SHA-1")
    validate_build_time(built_at)
    return (
        os.fspath(iscc),
        "/Qp",
        f"/DBundleRoot={bundle_root}",
        f"/DOutputRoot={output_root}",
        f"/DDisplayVersion={DISPLAY_VERSION}",
        f"/DFileVersion={FILE_VERSION}",
        f"/DSourceCommit={source_commit}",
        f"/DBuiltAt={built_at}",
        os.fspath(script),
    )


def compiler_sha256(path: Path) -> str:
    return _sha256_file(path, MAX_FILE_BYTES)


def verify_installer_script(contents: bytes) -> None:
    canonical = contents.replace(b"\r\n", b"\n")
    if b"\r" in canonical or INSTALLER_SCRIPT_SHA256 == "__SCRIPT_SHA256__":
        raise ValueError("installer script is not approved")
    if hashlib.sha256(canonical).hexdigest() != INSTALLER_SCRIPT_SHA256:
        raise ValueError("installer script is not approved")


def validate_preview_layout(bundle_root: Path) -> None:
    if not (bundle_root / GUI_LAUNCHER).is_file() or not (bundle_root / MCP_LAUNCHER).is_file():
        raise ValueError("integrations preview launcher layout is invalid")
    if not (bundle_root / "_internal" / "agentguardian").is_dir():
        raise ValueError("integrations preview package layout is invalid")
    skill = bundle_root / "agentguardian_skill"
    if not skill.is_dir() or {path.name for path in skill.iterdir()} != {
        "LICENSE",
        "README.md",
        "SKILL.md",
    }:
        raise ValueError("integrations preview Skill layout is invalid")


def build_installer(
    project_root: Path,
    bundle_root: Path,
    output_root: Path,
    *,
    iscc: Path,
    source_commit: str,
    built_at: str,
) -> Path:
    if sys.platform != "win32":
        raise RuntimeError("installer builds require Windows")
    project = project_root.resolve()
    bundle = bundle_root.resolve()
    output = output_root.resolve()
    compiler = iscc.resolve()
    if output.exists() or not compiler.is_file() or compiler_sha256(compiler) != COMPILER_SHA256:
        raise ValueError("installer compiler or output is invalid")
    head = _git(project, "rev-parse", "HEAD")
    status = _git(project, "status", "--porcelain=v1", "--untracked-files=all")
    validate_git_build_context(head, status, source_commit)
    profile_path = project / PROFILE_RELATIVE
    snapshot = load_profile_snapshot(project, profile_path)
    _require_current_source_identity(project, snapshot)
    verify_profile(project, snapshot)
    profile = snapshot.profile
    if (
        profile["name"] != PROFILE_NAME
        or profile["product_version"] != DISPLAY_VERSION
        or profile["windows_file_version"] != FILE_VERSION
        or profile["installer_app_id"] != APP_ID
        or profile["installer_filename"] != INSTALLER_NAME
    ):
        raise ValueError("integrations preview profile identity is invalid")
    script = project / SCRIPT_RELATIVE
    script_snapshot = script.read_bytes()
    verify_installer_script(script_snapshot)
    validate_preview_layout(bundle)
    verify_payload(bundle, snapshot)
    verify_profile_evidence(bundle, snapshot, source_commit)
    output.mkdir(parents=True)
    subprocess.run(
        build_iscc_command(
            iscc=compiler,
            script=script,
            bundle_root=bundle,
            output_root=output,
            source_commit=source_commit,
            built_at=built_at,
        ),
        cwd=project,
        check=True,
        shell=False,
    )
    final_head = _git(project, "rev-parse", "HEAD")
    final_status = _git(project, "status", "--porcelain=v1", "--untracked-files=all")
    validate_git_build_context(final_head, final_status, source_commit)
    require_profile_snapshot_unchanged(project, profile_path, snapshot)
    if script.read_bytes().replace(b"\r\n", b"\n") != script_snapshot.replace(b"\r\n", b"\n"):
        raise ValueError("installer script changed during build")
    verify_installer_script(script.read_bytes())
    validate_preview_layout(bundle)
    verify_payload(bundle, snapshot)
    verify_profile_evidence(bundle, snapshot, source_commit)
    installer = output / INSTALLER_NAME
    output_files = tuple(path for path in output.iterdir() if path.is_file())
    if output_files != (installer,) or installer.stat().st_size <= 0:
        raise ValueError("integrations preview installer output is invalid")
    return installer


def _sha256_file(path: Path, limit: int) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError("file exceeds verification limit")
            digest.update(chunk)
    return digest.hexdigest()


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ("git", *arguments),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--iscc", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--built-at", required=True)
    args = parser.parse_args()
    build_installer(
        args.project_root,
        args.bundle_root,
        args.output_root,
        iscc=args.iscc,
        source_commit=args.source_commit,
        built_at=args.built_at,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
