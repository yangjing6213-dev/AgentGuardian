"""Build and verify a bounded Microsoft Store candidate evidence chain."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from typing import Any
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from agentguardian.discovery import _has_reparse_component
from scripts.verify_wack_report import WackEvidenceError, read_msix_identity
from scripts.verify_windows_release_candidate import (
    ReleaseEvidenceError,
    _validate_license_review,
    _validate_sbom_and_notices,
)


MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024 * 1024
_MANIFEST_NAME = "release-manifest.json"
_CHECKSUM_NAME = "candidate-SHA256SUMS"
_EVIDENCE_FILES = {
    "license_review": "windows-license-review.json",
    "notices": "THIRD_PARTY_NOTICES.md",
    "payload_manifest": "payload-manifest.json",
    "privacy_result": "privacy-result.json",
    "profile_result": "profile-result.json",
    "provenance": "provenance.json",
    "sbom": "AgentGuardian.cdx.json",
    "wack_summary": "wack-summary.json",
    "workflow_run": "workflow-run.json",
}


class StoreCandidateError(ValueError):
    """Fixed-code failure for incomplete or inconsistent candidate evidence."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def create_candidate_evidence(
    evidence_root: str | Path, *, expected_source_commit: str
) -> dict[str, object]:
    root = _evidence_root(evidence_root)
    _require_source_commit(expected_source_commit)
    required = _core_names(expected_source_commit)
    _validate_exact_files(root, required, "STORE_CANDIDATE_INPUT_INVALID")
    manifest = _expected_manifest(root, expected_source_commit)
    manifest_path = root / _MANIFEST_NAME
    checksum_path = root / _CHECKSUM_NAME
    if manifest_path.exists() or checksum_path.exists():
        raise StoreCandidateError("STORE_CANDIDATE_OUTPUT_EXISTS")
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    checksum_path.write_bytes(_expected_checksums(root, expected_source_commit))
    return manifest


def validate_store_candidate(
    evidence_root: str | Path, *, expected_source_commit: str
) -> dict[str, object]:
    root = _evidence_root(evidence_root)
    _require_source_commit(expected_source_commit)
    validate_upload_allowlist(root, expected_source_commit)
    expected_manifest = _expected_manifest(root, expected_source_commit)
    manifest_path = root / _MANIFEST_NAME
    manifest = _json_file(manifest_path, "STORE_CANDIDATE_MANIFEST_INVALID")
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError:
        raise StoreCandidateError("STORE_CANDIDATE_MANIFEST_INVALID") from None
    if manifest != expected_manifest or manifest_bytes != canonical_json_bytes(manifest):
        raise StoreCandidateError("STORE_CANDIDATE_MANIFEST_MISMATCH")
    checksum_path = root / _CHECKSUM_NAME
    try:
        actual_checksums = checksum_path.read_bytes()
    except OSError:
        raise StoreCandidateError("STORE_CANDIDATE_CHECKSUMS_INVALID") from None
    if actual_checksums != _expected_checksums(root, expected_source_commit):
        raise StoreCandidateError("STORE_CANDIDATE_CHECKSUMS_INVALID")
    _validate_license(root, expected_source_commit)
    return {
        "license_review": "complete",
        "passed": True,
        "source_commit": expected_source_commit,
        "wack": "pass",
    }


def validate_upload_allowlist(
    evidence_root: str | Path, expected_source_commit: str
) -> tuple[Path, ...]:
    root = _evidence_root(evidence_root)
    _require_source_commit(expected_source_commit)
    return _validate_exact_files(
        root,
        _all_names(expected_source_commit),
        "STORE_EVIDENCE_ALLOWLIST_INVALID",
    )


def _expected_manifest(root: Path, source_commit: str) -> dict[str, object]:
    upload = root / _upload_name(source_commit)
    msix_entry, package_identity = _msixupload_package(upload, root)
    _validate_non_license_evidence(root, source_commit, msix_entry, package_identity)
    return {
        "evidence": {
            key: _file_entry(root / name) for key, name in _EVIDENCE_FILES.items()
        },
        "msix": msix_entry,
        "msixupload": _file_entry(upload),
        "package_identity": package_identity,
        "schema": 1,
        "source_commit": source_commit,
    }


def _validate_non_license_evidence(
    root: Path,
    source_commit: str,
    msix_entry: dict[str, object],
    package_identity: dict[str, str],
) -> None:
    payload = _json_file(
        root / _EVIDENCE_FILES["payload_manifest"],
        "STORE_CANDIDATE_PAYLOAD_MANIFEST_INVALID",
    )
    if (
        payload.get("schema") != 1
        or payload.get("algorithm") != "sha256"
        or not isinstance(payload.get("files"), list)
    ):
        raise StoreCandidateError("STORE_CANDIDATE_PAYLOAD_MANIFEST_INVALID")

    provenance = _json_file(
        root / _EVIDENCE_FILES["provenance"],
        "STORE_CANDIDATE_PROVENANCE_INVALID",
    )
    if (
        provenance.get("source_commit") != source_commit
        or provenance.get("artifact_status") != "store_submission_candidate"
    ):
        raise StoreCandidateError("STORE_CANDIDATE_PROVENANCE_INVALID")

    profile = _json_file(
        root / _EVIDENCE_FILES["profile_result"],
        "STORE_CANDIDATE_PROFILE_INVALID",
    )
    if profile != {"profile": "personal_store_release", "status": "pass"}:
        raise StoreCandidateError("STORE_CANDIDATE_PROFILE_INVALID")

    privacy = _json_file(
        root / _EVIDENCE_FILES["privacy_result"],
        "STORE_CANDIDATE_PRIVACY_INVALID",
    )
    if (
        privacy.get("schema") != 1
        or privacy.get("profile") != "personal_privacy_acceptance"
        or privacy.get("passed") is not True
    ):
        raise StoreCandidateError("STORE_CANDIDATE_PRIVACY_INVALID")

    sbom = _json_file(
        root / _EVIDENCE_FILES["sbom"], "STORE_CANDIDATE_SBOM_INVALID"
    )
    properties = sbom.get("metadata", {}).get("properties") if isinstance(sbom.get("metadata"), dict) else None
    if (
        sbom.get("bomFormat") != "CycloneDX"
        or not isinstance(sbom.get("components"), list)
        or not isinstance(properties, list)
        or not any(
            isinstance(item, dict)
            and item.get("name") == "agentguardian:build:id"
            and item.get("value") == source_commit
            for item in properties
        )
    ):
        raise StoreCandidateError("STORE_CANDIDATE_SBOM_INVALID")

    workflow = _json_file(
        root / _EVIDENCE_FILES["workflow_run"],
        "STORE_CANDIDATE_WORKFLOW_METADATA_INVALID",
    )
    session_id = workflow.get("wack_session_id")
    if (
        workflow.get("schema") != 1
        or workflow.get("source_commit") != source_commit
        or workflow.get("store_submission") != "not_performed"
        or workflow.get("wack_user_interactive") is not True
        or type(session_id) is not int
        or session_id == 0
        or "username" in {str(key).casefold() for key in workflow}
    ):
        raise StoreCandidateError("STORE_CANDIDATE_WORKFLOW_METADATA_INVALID")

    wack = _json_file(
        root / _EVIDENCE_FILES["wack_summary"],
        "STORE_CANDIDATE_WACK_INVALID",
    )
    counts = wack.get("test_counts")
    report_fields = wack.get("report_fields")
    package = wack.get("package_identity")
    if (
        set(wack)
        != {
            "generated_at",
            "overall_result",
            "package_identity",
            "package_sha256",
            "report_fields",
            "report_sha256",
            "schema",
            "source_commit",
            "source_commit_origin",
            "test_counts",
            "tool_version",
        }
        or wack.get("schema") != 2
        or wack.get("overall_result") != "PASS"
        or wack.get("source_commit") != source_commit
        or wack.get("source_commit_origin") != "candidate_input"
        or package != package_identity
        or not isinstance(package, dict)
        or set(package) != {"name", "processor_architecture", "publisher", "version"}
        or wack.get("package_sha256") != msix_entry["sha256"]
        or not _lower_hex(wack.get("report_sha256"), 64)
        or not _bounded_text(wack.get("tool_version"))
        or not isinstance(report_fields, dict)
        or set(report_fields)
        != {
            "app_name",
            "app_version",
            "id",
            "id_semantics",
            "publisher_display_name",
        }
        or report_fields.get("app_version") != package_identity["version"]
        or report_fields.get("id_semantics") != "unverified"
        or not _bounded_text(report_fields.get("app_name"))
        or not _bounded_text(report_fields.get("id"))
        or not isinstance(counts, dict)
        or set(counts) != {"failed", "passed", "requirements", "tests", "total"}
        or counts.get("failed") != 0
        or type(counts.get("total")) is not int
        or counts["total"] <= 0
        or counts.get("passed") != counts["total"]
        or counts.get("tests") != counts["total"]
        or type(counts.get("requirements")) is not int
        or counts["requirements"] <= 0
    ):
        raise StoreCandidateError("STORE_CANDIDATE_WACK_INVALID")
    _utc_seconds(wack.get("generated_at"), "STORE_CANDIDATE_WACK_INVALID")
    wack_path = root / _EVIDENCE_FILES["wack_summary"]
    try:
        if wack_path.read_bytes() != canonical_json_bytes(wack):
            raise StoreCandidateError("STORE_CANDIDATE_WACK_INVALID")
    except OSError:
        raise StoreCandidateError("STORE_CANDIDATE_WACK_INVALID") from None


def _validate_license(root: Path, source_commit: str) -> None:
    review_path = root / _EVIDENCE_FILES["license_review"]
    review = _json_file(review_path, "STORE_CANDIDATE_LICENSE_REVIEW_REQUIRED")
    if review.get("schema_version") != 1 or review.get("status") != "approved":
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_REVIEW_REQUIRED")
    if review.get("source_commit") != source_commit:
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_SOURCE_MISMATCH")
    sbom_path = root / _EVIDENCE_FILES["sbom"]
    if review.get("sbom_sha256") != _sha256_file(sbom_path):
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_SBOM_MISMATCH")
    try:
        component_licenses = _validate_sbom_and_notices(root)
        _validate_license_review(
            review_path,
            sbom_path,
            source_commit,
            component_licenses,
        )
    except ReleaseEvidenceError:
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_REVIEW_REQUIRED") from None


def _msixupload_package(
    upload: Path, evidence_root: Path
) -> tuple[dict[str, object], dict[str, str]]:
    try:
        with zipfile.ZipFile(upload) as archive:
            infos = archive.infolist()
            if (
                len(infos) != 1
                or infos[0].is_dir()
                or infos[0].flag_bits & 1
                or Path(infos[0].filename).name != infos[0].filename
                or not infos[0].filename.casefold().endswith(".msix")
                or infos[0].file_size <= 0
                or infos[0].file_size > MAX_EVIDENCE_BYTES
            ):
                raise StoreCandidateError("STORE_CANDIDATE_UPLOAD_INVALID")
            info = infos[0]
            with tempfile.TemporaryDirectory(
                prefix=".store-msix-", dir=evidence_root
            ) as temporary:
                extracted = Path(temporary) / info.filename
                with archive.open(info) as source, extracted.open("xb") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
                if extracted.stat().st_size != info.file_size:
                    raise StoreCandidateError("STORE_CANDIDATE_UPLOAD_INVALID")
                try:
                    package, identity = read_msix_identity(extracted)
                except WackEvidenceError:
                    raise StoreCandidateError("STORE_CANDIDATE_UPLOAD_INVALID") from None
                entry = {
                    "name": info.filename,
                    "sha256": _sha256_file(package),
                    "size": info.file_size,
                }
    except StoreCandidateError:
        raise
    except (OSError, MemoryError, RuntimeError, zipfile.BadZipFile):
        raise StoreCandidateError("STORE_CANDIDATE_UPLOAD_INVALID") from None
    return entry, identity


def _expected_checksums(root: Path, source_commit: str) -> bytes:
    names = sorted(_core_names(source_commit) | {_MANIFEST_NAME})
    return "".join(
        f"{_sha256_file(root / name)} *{name}\n" for name in names
    ).encode("ascii")


def _file_entry(path: Path) -> dict[str, object]:
    try:
        size = path.stat(follow_symlinks=False).st_size
    except OSError:
        raise StoreCandidateError("STORE_CANDIDATE_INPUT_INVALID") from None
    return {"name": path.name, "sha256": _sha256_file(path), "size": size}


def _json_file(path: Path, code: str) -> dict[str, Any]:
    try:
        if path.stat(follow_symlinks=False).st_size > MAX_JSON_BYTES:
            raise StoreCandidateError(code)
        value = json.loads(path.read_text(encoding="utf-8"))
    except StoreCandidateError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise StoreCandidateError(code) from None
    if not isinstance(value, dict):
        raise StoreCandidateError(code)
    return value


def _evidence_root(value: str | Path) -> Path:
    path = Path(value)
    if (
        not path.is_absolute()
        or path.anchor.startswith("\\\\")
        or path.is_symlink()
        or _has_reparse_component(path)
    ):
        raise StoreCandidateError("STORE_EVIDENCE_ROOT_INVALID")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise StoreCandidateError("STORE_EVIDENCE_ROOT_INVALID") from None
    if not resolved.is_dir():
        raise StoreCandidateError("STORE_EVIDENCE_ROOT_INVALID")
    return resolved


def _validate_exact_files(
    root: Path, expected_names: set[str], code: str
) -> tuple[Path, ...]:
    try:
        children = tuple(root.iterdir())
    except OSError:
        raise StoreCandidateError(code) from None
    if {path.name for path in children} != expected_names:
        raise StoreCandidateError(code)
    result: list[Path] = []
    for path in children:
        try:
            size = path.stat(follow_symlinks=False).st_size
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise StoreCandidateError(code) from None
        if (
            resolved.parent != root
            or not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode)
            or path.is_symlink()
            or _has_reparse_component(path)
            or size > MAX_EVIDENCE_BYTES
        ):
            raise StoreCandidateError(code)
        result.append(path)
    return tuple(sorted(result, key=lambda path: path.name))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise StoreCandidateError("STORE_CANDIDATE_INPUT_INVALID") from None
    return digest.hexdigest()


def _upload_name(source_commit: str) -> str:
    return f"AgentGuardian-{source_commit}.msixupload"


def _core_names(source_commit: str) -> set[str]:
    return {_upload_name(source_commit), *_EVIDENCE_FILES.values()}


def _all_names(source_commit: str) -> set[str]:
    return _core_names(source_commit) | {_MANIFEST_NAME, _CHECKSUM_NAME}


def _require_source_commit(value: object) -> None:
    if not _lower_hex(value, 40):
        raise StoreCandidateError("STORE_CANDIDATE_SOURCE_COMMIT_INVALID")


def _lower_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _bounded_text(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and len(value) <= 256
        and all(ord(character) >= 32 for character in value)
    )


def _utc_seconds(value: object, code: str) -> None:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        raise StoreCandidateError(code) from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise StoreCandidateError(code)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--create", action="store_true")
    mode.add_argument("--check-upload-allowlist", action="store_true")
    args = parser.parse_args()
    try:
        if args.create:
            result: object = create_candidate_evidence(
                args.evidence_root,
                expected_source_commit=args.expected_source_commit,
            )
        elif args.check_upload_allowlist:
            paths = validate_upload_allowlist(
                args.evidence_root, args.expected_source_commit
            )
            result = {"files": [path.name for path in paths], "status": "pass"}
        else:
            result = validate_store_candidate(
                args.evidence_root,
                expected_source_commit=args.expected_source_commit,
            )
    except StoreCandidateError as error:
        parser.error(str(error))
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
