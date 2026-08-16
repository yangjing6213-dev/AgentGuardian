"""Fail-closed final evidence gate for a trusted Windows release candidate."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from agentguardian.discovery import _has_reparse_component
from scripts.verify_personal_release_profile import (
    MAX_PROFILE_BYTES,
    ProfileSnapshot,
    ProfileViolation,
    canonical_json_bytes,
    profile_snapshot_from_bytes,
    require_profile_snapshot_unchanged,
    verify_payload,
    verify_profile,
)
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_FILES = 20_000
_UNKNOWN_LICENSES = frozenset({"NOASSERTION", "UNKNOWN", "NONE"})
_PACKAGE_NAME_PREFIX = "yangjing6213dev.AgentGuardian_"


class ReleaseEvidenceError(ValueError):
    """Raised when a release candidate is not supported by its evidence."""


def validate_release_candidate(
    bundle_root: str | Path,
    smoke_evidence_path: str | Path,
    *,
    expected_source_commit: str,
    require_trusted_signature: bool,
    require_fresh_user_state: bool,
    license_review_path: str | Path | None = None,
) -> dict[str, object]:
    bundle = _directory(bundle_root, "RELEASE_BUNDLE_INVALID")
    evidence = _json_file(smoke_evidence_path, "RELEASE_SMOKE_EVIDENCE_INVALID")
    if (
        type(expected_source_commit) is not str
        or len(expected_source_commit) != 40
        or any(character not in "0123456789abcdef" for character in expected_source_commit)
    ):
        raise ReleaseEvidenceError("RELEASE_SOURCE_COMMIT_INVALID")

    profile_path = ROOT / "release_profiles" / "personal_store_release.json"
    try:
        profile_snapshot = profile_snapshot_from_bytes(
            _profile_bytes_from_commit(expected_source_commit)
        )
    except ProfileViolation:
        raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_COMMIT_INVALID") from None
    try:
        require_profile_snapshot_unchanged(ROOT, profile_path, profile_snapshot)
    except ProfileViolation:
        raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_COMMIT_MISMATCH") from None
    try:
        verify_profile(ROOT, profile_snapshot)
    except ProfileViolation:
        raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_INVALID") from None
    _validate_personal_profile_evidence(bundle, profile_snapshot)
    try:
        verify_payload(bundle, profile_snapshot)
    except ProfileViolation:
        raise ReleaseEvidenceError("RELEASE_PERSONAL_PAYLOAD_INVALID") from None
    _validate_payload_integrity(bundle)

    metadata = _json_file(bundle / "BUILD-METADATA.json", "RELEASE_BUILD_METADATA_INVALID")
    if metadata.get("source_commit") != expected_source_commit:
        raise ReleaseEvidenceError("RELEASE_SOURCE_COMMIT_MISMATCH")

    component_licenses = _validate_sbom_and_notices(bundle)
    if require_trusted_signature:
        _validate_license_review(
            license_review_path,
            bundle / "AgentGuardian.cdx.json",
            expected_source_commit,
            component_licenses,
        )
    if metadata.get("artifact_status") != "trusted_release":
        raise ReleaseEvidenceError("RELEASE_ARTIFACT_STATUS_UNTRUSTED")
    signature_mode = evidence.get("signature_mode")
    signature = evidence.get("signature")
    result = evidence.get("result")
    if not isinstance(signature, dict) or not isinstance(result, dict):
        raise ReleaseEvidenceError("RELEASE_SMOKE_EVIDENCE_INVALID")
    if require_trusted_signature and (
        signature_mode != "trusted_signed" or signature.get("status") != "Valid"
    ):
        raise ReleaseEvidenceError("RELEASE_TRUSTED_SIGNATURE_REQUIRED")
    if evidence.get("source_commit") != expected_source_commit:
        raise ReleaseEvidenceError("RELEASE_SMOKE_SOURCE_COMMIT_MISMATCH")
    package_full_name = evidence.get("package_full_name")
    if not _is_package_full_name(package_full_name):
        raise ReleaseEvidenceError("RELEASE_PACKAGE_IDENTITY_INVALID")
    if require_fresh_user_state and (
        evidence.get("fresh_user_state") is not True
        or result.get("app_data_residue") is not False
    ):
        raise ReleaseEvidenceError("RELEASE_FRESH_USER_STATE_REQUIRED")
    for key in ("process_startup", "bounded_liveness", "termination", "uninstalled"):
        if result.get(key) is not True:
            raise ReleaseEvidenceError(f"RELEASE_SMOKE_{key.upper()}_FAILED")
    if result.get("package_residue") is not False:
        raise ReleaseEvidenceError("RELEASE_PACKAGE_RESIDUE")
    return {
        "passed": True,
        "source_commit": expected_source_commit,
        "signature_mode": signature_mode,
        "fresh_user_state": evidence.get("fresh_user_state") is True,
        "license_review": "complete",
    }


def _validate_personal_profile_evidence(
    bundle: Path, profile_snapshot: ProfileSnapshot
) -> None:
    evidence_path = bundle / "PERSONAL-RELEASE-PROFILE.json"
    evidence = _json_file(
        evidence_path,
        "RELEASE_PERSONAL_PROFILE_EVIDENCE_INVALID",
    )
    expected_keys = {"profile", "profile_sha256", "schema", "status"}
    if (
        set(evidence) != expected_keys
        or evidence.get("profile") != "personal_store_release"
        or type(evidence.get("schema")) is not int
        or evidence.get("schema") != 1
        or evidence.get("status") != "pass"
    ):
        raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_EVIDENCE_INVALID")
    try:
        if evidence_path.read_bytes() != canonical_json_bytes(evidence):
            raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_EVIDENCE_INVALID")
    except OSError:
        raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_EVIDENCE_INVALID") from None
    if evidence.get("profile_sha256") != profile_snapshot.sha256:
        raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_MISMATCH")


def _validate_payload_integrity(bundle: Path) -> None:
    manifest_path = bundle / "PAYLOAD-MANIFEST.json"
    manifest = _json_file(manifest_path, "RELEASE_PAYLOAD_MANIFEST_INVALID")
    if set(manifest) != {"algorithm", "files", "schema"} or (
        manifest.get("algorithm") != "sha256" or manifest.get("schema") != 1
    ):
        raise ReleaseEvidenceError("RELEASE_PAYLOAD_MANIFEST_INVALID")
    try:
        if manifest_path.read_bytes() != canonical_json_bytes(manifest):
            raise ReleaseEvidenceError("RELEASE_PAYLOAD_MANIFEST_INVALID")
    except OSError:
        raise ReleaseEvidenceError("RELEASE_PAYLOAD_MANIFEST_INVALID") from None
    files = _integrity_files(bundle)
    payload_files = tuple(
        path
        for path in files
        if path.name not in {"PAYLOAD-MANIFEST.json", "SHA256SUMS"}
    )
    expected_manifest = [_integrity_entry(bundle, path) for path in payload_files]
    if manifest.get("files") != expected_manifest:
        raise ReleaseEvidenceError("RELEASE_PAYLOAD_MANIFEST_INVALID")

    checksum_path = _safe_local_path(bundle / "SHA256SUMS", "RELEASE_CHECKSUMS_INVALID")
    try:
        if not _regular_file(checksum_path) or checksum_path.stat().st_size > MAX_JSON_BYTES:
            raise ReleaseEvidenceError("RELEASE_CHECKSUMS_INVALID")
        actual = checksum_path.read_bytes()
    except OSError:
        raise ReleaseEvidenceError("RELEASE_CHECKSUMS_INVALID") from None
    checksum_files = tuple(path for path in files if path.name != "SHA256SUMS")
    expected = "".join(
        f"{_sha256_file(path)} *{path.relative_to(bundle).as_posix()}\n"
        for path in checksum_files
    ).encode("ascii")
    if actual != expected:
        raise ReleaseEvidenceError("RELEASE_CHECKSUMS_INVALID")


def _integrity_files(bundle: Path) -> tuple[Path, ...]:
    try:
        files = tuple(
            sorted(
                (path for path in bundle.rglob("*") if path.is_file()),
                key=lambda path: path.relative_to(bundle).as_posix(),
            )
        )
    except OSError:
        raise ReleaseEvidenceError("RELEASE_PAYLOAD_MANIFEST_INVALID") from None
    if len(files) > MAX_MANIFEST_FILES:
        raise ReleaseEvidenceError("RELEASE_PAYLOAD_MANIFEST_INVALID")
    folded: set[str] = set()
    for path in files:
        relative = path.relative_to(bundle).as_posix()
        pure = PurePosixPath(relative)
        if (
            not relative
            or "\\" in relative
            or pure.is_absolute()
            or any(part in {"", ".", ".."} for part in pure.parts)
            or relative.casefold() in folded
            or _has_reparse_component(path)
        ):
            raise ReleaseEvidenceError("RELEASE_PAYLOAD_MANIFEST_INVALID")
        folded.add(relative.casefold())
    return files


def _integrity_entry(bundle: Path, path: Path) -> dict[str, object]:
    try:
        size = path.stat(follow_symlinks=False).st_size
    except OSError:
        raise ReleaseEvidenceError("RELEASE_PAYLOAD_MANIFEST_INVALID") from None
    return {
        "path": path.relative_to(bundle).as_posix(),
        "sha256": _sha256_file(path),
        "size": size,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise ReleaseEvidenceError("RELEASE_PAYLOAD_MANIFEST_INVALID") from None
    return digest.hexdigest()


def _regular_file(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and not _has_reparse_component(path)
    except OSError:
        return False


def _profile_bytes_from_commit(source_commit: str) -> bytes:
    object_name = f"{source_commit}:release_profiles/personal_store_release.json"
    try:
        size_result = subprocess.run(
            (
                "git",
                "cat-file",
                "-s",
                object_name,
            ),
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        size_text = size_result.stdout.strip()
        if (
            size_result.returncode != 0
            or not size_text
            or len(size_text) > 20
            or not size_text.isdigit()
            or (len(size_text) > 1 and size_text.startswith(b"0"))
        ):
            raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_COMMIT_INVALID")
        size = int(size_text)
        if size == 0 or size > MAX_PROFILE_BYTES:
            raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_COMMIT_INVALID")

        blob_result = subprocess.run(
            ("git", "show", object_name),
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        value = blob_result.stdout
        if blob_result.returncode != 0 or len(value) != size:
            raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_COMMIT_INVALID")
        return value
    except ReleaseEvidenceError:
        raise
    except (MemoryError, OSError, OverflowError, subprocess.TimeoutExpired):
        raise ReleaseEvidenceError("RELEASE_PERSONAL_PROFILE_COMMIT_INVALID") from None


def _is_package_full_name(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and len(value) <= 256
        and "\x00" not in value
        and value.startswith(_PACKAGE_NAME_PREFIX)
    )


def _validate_sbom_and_notices(bundle: Path) -> dict[tuple[str, str], str]:
    sbom = _json_file(bundle / "AgentGuardian.cdx.json", "RELEASE_SBOM_INVALID")
    if sbom.get("bomFormat") != "CycloneDX" or not isinstance(sbom.get("components"), list):
        raise ReleaseEvidenceError("RELEASE_SBOM_INVALID")
    notices_path = bundle / "THIRD_PARTY_NOTICES.md"
    if not notices_path.is_file():
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
    notices = notices_path.read_text(encoding="utf-8")
    component_licenses: dict[tuple[str, str], str] = {}
    for component in sbom["components"]:
        if not isinstance(component, dict):
            raise ReleaseEvidenceError("RELEASE_SBOM_INVALID")
        name = component.get("name")
        version = component.get("version")
        licenses = component.get("licenses")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise ReleaseEvidenceError("RELEASE_SBOM_INVALID")
        if not isinstance(licenses, list) or not licenses:
            raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
        if f"{name} {version}" not in notices:
            raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
        identifiers: list[str] = []
        for entry in licenses:
            if not isinstance(entry, dict):
                raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
            license_data = entry.get("license")
            expression = entry.get("expression")
            identifier: object = expression
            if isinstance(license_data, dict):
                identifier = license_data.get("id") or license_data.get("name")
            if not isinstance(identifier, str) or not identifier or identifier.upper() in _UNKNOWN_LICENSES:
                raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
            identifiers.append(identifier)
        key = (name, version)
        if key in component_licenses:
            raise ReleaseEvidenceError("RELEASE_SBOM_INVALID")
        component_licenses[key] = ";".join(identifiers)
    return component_licenses


def _validate_license_review(
    review_path: str | Path | None,
    sbom_path: Path,
    expected_source_commit: str,
    component_licenses: dict[tuple[str, str], str],
) -> None:
    if review_path is None:
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
    review = _json_file(review_path, "RELEASE_LICENSE_REVIEW_REQUIRED")
    if review.get("schema_version") != 1 or review.get("status") != "approved":
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
    if review.get("source_commit") != expected_source_commit:
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_SOURCE_COMMIT_MISMATCH")
    sbom_digest = review.get("sbom_sha256")
    if (
        type(sbom_digest) is not str
        or len(sbom_digest) != 64
        or any(character not in "0123456789abcdef" for character in sbom_digest)
    ):
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
    try:
        actual_sbom_digest = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
    except OSError:
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED") from None
    if sbom_digest != actual_sbom_digest:
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
    reviewer = review.get("reviewer")
    reviewed_at = review.get("reviewed_at")
    if (
        type(reviewer) is not str
        or not reviewer.strip()
        or type(reviewed_at) is not str
    ):
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
    try:
        parsed_reviewed_at = datetime.strptime(reviewed_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED") from None
    if parsed_reviewed_at.strftime("%Y-%m-%dT%H:%M:%SZ") != reviewed_at:
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
    components = review.get("components")
    if not isinstance(components, list) or len(components) != len(component_licenses):
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
    expected_fields = {
        "name",
        "version",
        "license_expression",
        "redistribution",
        "evidence_url",
    }
    seen: set[tuple[str, str]] = set()
    for component in components:
        if not isinstance(component, dict) or set(component) != expected_fields:
            raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
        name = component.get("name")
        version = component.get("version")
        key = (name, version) if isinstance(name, str) and isinstance(version, str) else None
        expression = component.get("license_expression")
        evidence_url = component.get("evidence_url")
        if (
            key is None
            or key in seen
            or key not in component_licenses
            or expression != component_licenses[key]
            or component.get("redistribution") != "approved"
            or type(evidence_url) is not str
            or not evidence_url.startswith("https://")
            or any(character.isspace() for character in evidence_url)
        ):
            raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")
        seen.add(key)
    if seen != set(component_licenses):
        raise ReleaseEvidenceError("RELEASE_LICENSE_REVIEW_REQUIRED")


def _directory(value: str | Path, code: str) -> Path:
    path = _safe_local_path(value, code)
    if not path.is_dir():
        raise ReleaseEvidenceError(code)
    return path


def _json_file(value: str | Path, code: str) -> dict[str, Any]:
    path = _safe_local_path(value, code)
    if not path.is_file():
        raise ReleaseEvidenceError(code)
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ReleaseEvidenceError(code)
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ReleaseEvidenceError(code) from None
    if not isinstance(value, dict):
        raise ReleaseEvidenceError(code)
    return value


def _safe_local_path(value: str | Path, code: str) -> Path:
    path = Path(value)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or path.anchor.startswith("\\\\")
        or _has_reparse_component(path)
    ):
        raise ReleaseEvidenceError(code)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--smoke-evidence", type=Path, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--require-trusted-signature", action="store_true")
    parser.add_argument("--require-fresh-user-state", action="store_true")
    parser.add_argument("--license-review", type=Path)
    args = parser.parse_args()
    try:
        result = validate_release_candidate(
            args.bundle_root,
            args.smoke_evidence,
            expected_source_commit=args.expected_source_commit,
            require_trusted_signature=args.require_trusted_signature,
            require_fresh_user_state=args.require_fresh_user_state,
            license_review_path=args.license_review,
        )
    except ReleaseEvidenceError as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
