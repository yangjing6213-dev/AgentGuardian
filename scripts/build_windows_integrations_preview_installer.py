"""Build and verify the unsigned 0.3 integrations-preview installer."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.build_windows_installer import verify_payload_integrity
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
    verify_payload,
    verify_profile,
    verify_profile_evidence,
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
INSTALLER_SCRIPT_SHA256 = "c8d523107e5cfc1f1f72d1e409a20bba4048a5eb2ec1381b5b827c341537c580"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_INSTALLER_BYTES = 2 * 1024 * 1024 * 1024
INSTALLER_ATTESTATION_SUFFIX = ".build.json"
INSTALLER_DISCLOSURE_MARKERS = (
    b"AgentGuardian 0.3.0 Public Preview (unsigned).",
    b"Use only personal non-regulated configuration data.",
    b"Windows may show Unknown Publisher or SmartScreen warnings.",
    b"Reports and redacted results may be visible to the configured host.",
)


def installer_attestation_path(installer: Path) -> Path:
    """Return the out-of-band provenance path for an installer artifact."""
    resolved = Path(installer).absolute()
    return resolved.parent.parent / f"{resolved.name}{INSTALLER_ATTESTATION_SUFFIX}"


def _sha256_file_with_size(path: Path, limit: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise ValueError("file exceeds verification limit")
                digest.update(chunk)
    except ValueError:
        raise
    except OSError:
        raise ValueError("installer attestation input is invalid") from None
    return digest.hexdigest(), size


def _canonical_script_sha256(path: Path) -> str:
    try:
        contents = path.read_bytes()
    except OSError:
        raise ValueError("installer attestation input is invalid") from None
    if len(contents) > MAX_FILE_BYTES:
        raise ValueError("installer attestation input is invalid")
    canonical = contents.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(canonical).hexdigest()


def _write_attestation_bytes(target: Path, contents: bytes) -> None:
    if not target.is_absolute() or target.exists() or not target.parent.is_dir():
        message = (
            "installer attestation already exists"
            if target.exists()
            else "installer attestation path is invalid"
        )
        raise ValueError(message)
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", dir=target.parent
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        if target.exists():
            raise ValueError("installer attestation already exists")
        os.replace(temporary, target)
        temporary = None
    except ValueError:
        raise
    except OSError:
        raise ValueError("installer attestation write failed") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


def write_installer_attestation(
    installer: Path,
    bundle_root: Path,
    *,
    project_root: Path,
    profile_snapshot: ProfileSnapshot,
    source_commit: str,
    built_at: str,
    attestation_path: Path | None = None,
) -> Path:
    """Write one canonical, out-of-band build provenance document."""
    if not isinstance(profile_snapshot, ProfileSnapshot):
        raise TypeError("installer attestation profile is invalid")
    validate_build_time(built_at)
    if len(source_commit) != 40 or any(
        character not in "0123456789abcdef" for character in source_commit
    ):
        raise ValueError("source commit must be a full lowercase SHA-1")
    installer = Path(installer).absolute()
    bundle = Path(bundle_root).absolute()
    project = Path(project_root).absolute()
    target = (
        Path(attestation_path).absolute()
        if attestation_path
        else installer_attestation_path(installer)
    )
    if not installer.is_file() or not bundle.is_dir() or not project.is_dir():
        raise ValueError("installer attestation input is invalid")
    if (
        target.name != INSTALLER_NAME + INSTALLER_ATTESTATION_SUFFIX
        or not target.is_absolute()
        or target == installer.parent
        or installer.parent in target.parents
    ):
        raise ValueError("installer attestation path is invalid")
    installer_digest, installer_size = _sha256_file_with_size(
        installer, MAX_INSTALLER_BYTES
    )
    profile = profile_snapshot.profile
    script = project / str(profile["inno_setup_script"])
    bundle_names = {
        "build_metadata_sha256": "BUILD-METADATA.json",
        "profile_evidence_sha256": "INTEGRATIONS-PREVIEW-PROFILE.json",
        "payload_manifest_sha256": "PAYLOAD-MANIFEST.json",
        "checksums_sha256": "SHA256SUMS",
    }
    bundle_digests: dict[str, str] = {}
    for key, name in bundle_names.items():
        path = bundle / name
        if not path.is_file():
            raise ValueError("installer attestation input is invalid")
        bundle_digests[key], _ = _sha256_file_with_size(path, MAX_FILE_BYTES)
    value = {
        "artifact_name": INSTALLER_NAME,
        "artifact_sha256": installer_digest,
        "artifact_size": installer_size,
        "artifact_status": profile["release_artifact_status"],
        "built_at": built_at,
        "bundle": bundle_digests,
        "compiler_sha256": profile["inno_setup_iscc_sha256"],
        "compiler_version": profile["inno_setup_version"],
        "installer_script_sha256": _canonical_script_sha256(script),
        "profile": PROFILE_NAME,
        "profile_sha256": profile_snapshot.sha256,
        "schema": 1,
        "source_commit": source_commit,
        "version": profile["product_version"],
    }
    _write_attestation_bytes(target, canonical_json_bytes(value))
    return target


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
    if (
        b"\r" in canonical
        or INSTALLER_SCRIPT_SHA256 == "__SCRIPT_SHA256__"
        or any(marker not in canonical for marker in INSTALLER_DISCLOSURE_MARKERS)
    ):
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
    attestation_path: Path | None = None,
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
    verify_payload_integrity(bundle)
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
    verify_payload_integrity(bundle)
    verify_profile_evidence(bundle, snapshot, source_commit)
    installer = output / INSTALLER_NAME
    output_files = tuple(path for path in output.iterdir() if path.is_file())
    if output_files != (installer,) or installer.stat().st_size <= 0:
        raise ValueError("integrations preview installer output is invalid")
    write_installer_attestation(
        installer,
        bundle,
        project_root=project,
        profile_snapshot=snapshot,
        source_commit=source_commit,
        built_at=built_at,
        attestation_path=attestation_path,
    )
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
    parser.add_argument("--attestation-path", type=Path)
    args = parser.parse_args()
    build_installer(
        args.project_root,
        args.bundle_root,
        args.output_root,
        iscc=args.iscc,
        source_commit=args.source_commit,
        built_at=args.built_at,
        attestation_path=args.attestation_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
