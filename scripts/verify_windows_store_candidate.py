"""Build and verify a bounded Microsoft Store candidate evidence chain."""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
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
MAX_MSIX_BYTES = 512 * 1024 * 1024
MAX_MSIXUPLOAD_BYTES = 512 * 1024 * 1024
MAX_INNER_ENTRY_BYTES = 256 * 1024 * 1024
MAX_INNER_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_EVIDENCE_ROOT_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_FILES = 20_000
MAX_APPROVED_LICENSE_REVIEW_BYTES = 256 * 1024
MAX_APPROVED_LICENSE_REVIEW_BASE64_BYTES = (
    4 * ((MAX_APPROVED_LICENSE_REVIEW_BYTES + 2) // 3)
)
_MANIFEST_NAME = "release-manifest.json"
_CHECKSUM_NAME = "candidate-SHA256SUMS"
_EVIDENCE_FILES = {
    "license_review": "windows-license-review.json",
    "notices": "THIRD_PARTY_NOTICES.md",
    "payload_manifest": "payload-manifest.json",
    "portable_checksums": "portable-SHA256SUMS",
    "privacy_result": "privacy-result.json",
    "profile_result": "profile-result.json",
    "provenance": "provenance.json",
    "sbom": "AgentGuardian.cdx.json",
    "wack_summary": "wack-summary.json",
    "workflow_run": "workflow-run.json",
}
_PORTABLE_SIDECARS = {
    "AgentGuardian.cdx.json": "AgentGuardian.cdx.json",
    "BUILD-METADATA.json": "provenance.json",
    "PAYLOAD-MANIFEST.json": "payload-manifest.json",
    "SHA256SUMS": "portable-SHA256SUMS",
    "THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md",
}
_MSIX_WRAPPER_FILES = {
    "AppxBlockMap.xml",
    "AppxManifest.xml",
    "[Content_Types].xml",
}
_MSIX_ASSET_FILES = (
    "Assets/Square44x44Logo.png",
    "Assets/Square150x150Logo.png",
    "Assets/StoreLogo.png",
)


class StoreCandidateError(ValueError):
    """Fixed-code failure for incomplete or inconsistent candidate evidence."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def materialize_license_review(
    evidence_root: str | Path,
    repository_template: str | Path,
    approved_base64: str,
    *,
    expected_source_commit: str,
) -> str:
    root = _evidence_root(evidence_root)
    _require_source_commit(expected_source_commit)
    output = root / _EVIDENCE_FILES["license_review"]
    if output.exists() or type(approved_base64) is not str:
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_INPUT_INVALID")
    if approved_base64 == "":
        template = _regular_local_file(
            repository_template, "STORE_CANDIDATE_LICENSE_TEMPLATE_INVALID"
        )
        template_value = _json_file(
            template, "STORE_CANDIDATE_LICENSE_TEMPLATE_INVALID"
        )
        if (
            not _schema_is(template_value, "schema_version", 1)
            or template_value.get("status") != "pending"
            or any(
                template_value.get(key) is not None
                for key in ("source_commit", "sbom_sha256", "reviewed_at", "reviewer")
            )
            or not isinstance(template_value.get("components"), list)
            or not template_value["components"]
            or any(
                not isinstance(component, dict)
                or component.get("redistribution") != "pending"
                for component in template_value["components"]
            )
        ):
            raise StoreCandidateError("STORE_CANDIDATE_LICENSE_TEMPLATE_INVALID")
        try:
            with template.open("rb") as source, output.open("xb") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
        except OSError:
            raise StoreCandidateError(
                "STORE_CANDIDATE_LICENSE_TEMPLATE_INVALID"
            ) from None
        return "repository_pending_template"

    if (
        len(approved_base64) > MAX_APPROVED_LICENSE_REVIEW_BASE64_BYTES
        or not approved_base64.isascii()
    ):
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_INPUT_INVALID")
    try:
        raw = base64.b64decode(approved_base64, validate=True)
    except (binascii.Error, ValueError):
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_INPUT_INVALID") from None
    if not raw or len(raw) > MAX_APPROVED_LICENSE_REVIEW_BYTES:
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_INPUT_INVALID")
    try:
        review = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_INPUT_INVALID") from None
    if not isinstance(review, dict) or raw != canonical_json_bytes(review):
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_INPUT_INVALID")
    _validate_external_license_shape(review)
    if review["source_commit"] != expected_source_commit:
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_SOURCE_MISMATCH")
    sbom_path = root / _EVIDENCE_FILES["sbom"]
    if review["sbom_sha256"] != _sha256_file(sbom_path):
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_SBOM_MISMATCH")
    try:
        with output.open("xb") as handle:
            handle.write(raw)
    except OSError:
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_INPUT_INVALID") from None
    return "workflow_dispatch_input"


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
    if (
        not _schema_is(manifest, "schema", 1)
        or manifest != expected_manifest
        or manifest_bytes != canonical_json_bytes(manifest)
    ):
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
    msix_entry, package_identity, assets = _msixupload_package(upload, root)
    _validate_non_license_evidence(root, source_commit, msix_entry, package_identity)
    return {
        "assets": assets,
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
        not _schema_is(payload, "schema", 1)
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
        not _schema_is(privacy, "schema", 1)
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
    workflow_keys = {str(key).casefold() for key in workflow}
    license_origin = workflow.get("license_review_origin")
    if (
        not _schema_is(workflow, "schema", 1)
        or workflow.get("source_commit") != source_commit
        or workflow.get("store_submission") != "not_performed"
        or workflow.get("wack_session_state") != "active"
        or license_origin
        not in {"repository_pending_template", "workflow_dispatch_input"}
        or workflow_keys
        & {
            "approved_license_review_base64",
            "username",
            "wack_session_id",
            "wack_user_interactive",
        }
    ):
        raise StoreCandidateError("STORE_CANDIDATE_WORKFLOW_METADATA_INVALID")

    wack = _json_file(
        root / _EVIDENCE_FILES["wack_summary"],
        "STORE_CANDIDATE_WACK_INVALID",
    )
    counts = wack.get("test_counts")
    report_fields = wack.get("report_fields")
    package = wack.get("package_identity")
    invocation = wack.get("invocation")
    if (
        set(wack)
        != {
            "generated_at",
            "invocation",
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
        or not _schema_is(wack, "schema", 2)
        or wack.get("overall_result") != "PASS"
        or wack.get("source_commit") != source_commit
        or wack.get("source_commit_origin") != "candidate_input"
        or package != package_identity
        or not isinstance(package, dict)
        or set(package) != {"name", "processor_architecture", "publisher", "version"}
        or wack.get("package_sha256") != msix_entry["sha256"]
        or not _lower_hex(wack.get("report_sha256"), 64)
        or not _bounded_text(wack.get("tool_version"))
        or not isinstance(invocation, dict)
        or set(invocation)
        != {
            "binding_mode",
            "package_sha_after",
            "package_sha_before",
            "report_created_after_start",
            "started_at",
        }
        or invocation.get("binding_mode") != "same_process_invocation"
        or invocation.get("package_sha_before") != msix_entry["sha256"]
        or invocation.get("package_sha_after") != msix_entry["sha256"]
        or invocation.get("report_created_after_start") is not True
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
    _utc_seconds(invocation.get("started_at"), "STORE_CANDIDATE_WACK_INVALID")
    if invocation["started_at"] > wack["generated_at"]:
        raise StoreCandidateError("STORE_CANDIDATE_WACK_INVALID")
    wack_path = root / _EVIDENCE_FILES["wack_summary"]
    try:
        if wack_path.read_bytes() != canonical_json_bytes(wack):
            raise StoreCandidateError("STORE_CANDIDATE_WACK_INVALID")
    except OSError:
        raise StoreCandidateError("STORE_CANDIDATE_WACK_INVALID") from None


def _validate_license(root: Path, source_commit: str) -> None:
    review_path = root / _EVIDENCE_FILES["license_review"]
    review = _json_file(review_path, "STORE_CANDIDATE_LICENSE_REVIEW_REQUIRED")
    workflow = _json_file(
        root / _EVIDENCE_FILES["workflow_run"],
        "STORE_CANDIDATE_WORKFLOW_METADATA_INVALID",
    )
    if (
        not _schema_is(review, "schema_version", 1)
        or review.get("status") != "approved"
    ):
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_REVIEW_REQUIRED")
    if workflow.get("license_review_origin") != "workflow_dispatch_input":
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
) -> tuple[dict[str, object], dict[str, str], list[dict[str, object]]]:
    try:
        if upload.stat(follow_symlinks=False).st_size > MAX_MSIXUPLOAD_BYTES:
            raise StoreCandidateError("STORE_CANDIDATE_UPLOAD_INVALID")
        with zipfile.ZipFile(upload) as archive:
            infos = archive.infolist()
            if (
                len(infos) != 1
                or infos[0].is_dir()
                or infos[0].flag_bits & 1
                or infos[0].compress_type != zipfile.ZIP_STORED
                or infos[0].compress_size != infos[0].file_size
                or Path(infos[0].filename).name != infos[0].filename
                or not infos[0].filename.casefold().endswith(".msix")
                or infos[0].file_size <= 0
                or infos[0].file_size > MAX_MSIX_BYTES
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
                assets = _validate_msix_portable_evidence(package, evidence_root)
                entry = {
                    "name": info.filename,
                    "sha256": _sha256_file(package),
                    "size": info.file_size,
                }
    except StoreCandidateError:
        raise
    except (OSError, MemoryError, RuntimeError, zipfile.BadZipFile):
        raise StoreCandidateError("STORE_CANDIDATE_UPLOAD_INVALID") from None
    return entry, identity, assets


def _validate_msix_portable_evidence(
    package: Path, evidence_root: Path
) -> list[dict[str, object]]:
    try:
        with zipfile.ZipFile(package) as archive:
            portable: dict[str, zipfile.ZipInfo] = {}
            wrapper_files: set[str] = set()
            asset_infos: dict[str, zipfile.ZipInfo] = {}
            seen: set[str] = set()
            infos = archive.infolist()
            if len(infos) > MAX_MANIFEST_FILES + 10:
                raise StoreCandidateError(
                    "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                )
            total_uncompressed = 0
            for info in infos:
                name = _safe_archive_name(info.filename)
                folded = name.casefold()
                if folded in seen or info.flag_bits & 1:
                    raise StoreCandidateError(
                        "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                )
                seen.add(folded)
                if info.is_dir():
                    if _reserved_wrapper_path(name):
                        raise StoreCandidateError(
                            "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                        )
                    continue
                if info.file_size < 0 or info.file_size > MAX_INNER_ENTRY_BYTES:
                    raise StoreCandidateError(
                        "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                    )
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_INNER_UNCOMPRESSED_BYTES:
                    raise StoreCandidateError(
                        "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                    )
                if name in _MSIX_WRAPPER_FILES:
                    wrapper_files.add(name)
                    continue
                if name in _MSIX_ASSET_FILES:
                    asset_infos[name] = info
                    continue
                if _reserved_wrapper_path(name):
                    raise StoreCandidateError(
                        "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                    )
                portable[name] = info
            if (
                not portable
                or len(portable) > MAX_MANIFEST_FILES
                or not _MSIX_WRAPPER_FILES.issubset(wrapper_files)
                or set(asset_infos) != set(_MSIX_ASSET_FILES)
            ):
                raise StoreCandidateError(
                    "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                )
            for internal, external in _PORTABLE_SIDECARS.items():
                info = portable.get(internal)
                if info is None:
                    raise StoreCandidateError(
                        "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                    )
                internal_bytes = _zip_entry_bytes(archive, info, MAX_JSON_BYTES)
                try:
                    external_path = evidence_root / external
                    if external_path.stat(follow_symlinks=False).st_size > MAX_JSON_BYTES:
                        raise StoreCandidateError(
                            "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                        )
                    external_bytes = external_path.read_bytes()
                except OSError:
                    raise StoreCandidateError(
                        "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                    ) from None
                if internal_bytes != external_bytes:
                    raise StoreCandidateError(
                        "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                    )

            actual: dict[str, tuple[int, str]] = {}
            for name, info in portable.items():
                actual[name] = (info.file_size, _zip_entry_sha256(archive, info))
            payload_raw = _zip_entry_bytes(
                archive, portable["PAYLOAD-MANIFEST.json"], MAX_JSON_BYTES
            )
            checksums_raw = _zip_entry_bytes(
                archive, portable["SHA256SUMS"], MAX_JSON_BYTES
            )
            assets = [
                {
                    "name": name,
                    "sha256": _zip_entry_sha256(archive, asset_infos[name]),
                    "size": asset_infos[name].file_size,
                }
                for name in _MSIX_ASSET_FILES
            ]
    except StoreCandidateError:
        raise
    except (OSError, MemoryError, RuntimeError, zipfile.BadZipFile):
        raise StoreCandidateError(
            "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
        ) from None
    _validate_payload_manifest(payload_raw, actual)
    _validate_portable_checksums(checksums_raw, actual)
    return assets


def _validate_payload_manifest(
    raw: bytes, actual: dict[str, tuple[int, str]]
) -> None:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise StoreCandidateError(
            "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
        ) from None
    if (
        not isinstance(value, dict)
        or raw != canonical_json_bytes(value)
        or set(value) != {"algorithm", "files", "schema"}
        or value.get("algorithm") != "sha256"
        or not _schema_is(value, "schema", 1)
        or not isinstance(value.get("files"), list)
        or not value["files"]
        or len(value["files"]) > MAX_MANIFEST_FILES
    ):
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")
    entries: dict[str, tuple[int, str]] = {}
    folded: set[str] = set()
    for entry in value["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise StoreCandidateError(
                "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
            )
        path = _safe_manifest_path(entry.get("path"))
        size = entry.get("size")
        digest = entry.get("sha256")
        if (
            path.casefold() in folded
            or type(size) is not int
            or size < 0
            or size > MAX_INNER_ENTRY_BYTES
            or not _lower_hex(digest, 64)
        ):
            raise StoreCandidateError(
                "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
            )
        folded.add(path.casefold())
        entries[path] = (size, digest)
    expected_names = set(actual) - {"PAYLOAD-MANIFEST.json", "SHA256SUMS"}
    if set(entries) != expected_names or any(
        entries[name] != actual[name] for name in entries
    ):
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")


def _validate_portable_checksums(
    raw: bytes, actual: dict[str, tuple[int, str]]
) -> None:
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise StoreCandidateError(
            "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
        ) from None
    if not text or not text.endswith("\n") or "\r" in text:
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")
    entries: dict[str, str] = {}
    folded: set[str] = set()
    lines = text.splitlines()
    if not lines or len(lines) > MAX_MANIFEST_FILES:
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")
    for line in lines:
        if len(line) < 67 or line[64:66] != " *":
            raise StoreCandidateError(
                "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
            )
        digest = line[:64]
        path = _safe_manifest_path(line[66:])
        if not _lower_hex(digest, 64) or path.casefold() in folded:
            raise StoreCandidateError(
                "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
            )
        folded.add(path.casefold())
        entries[path] = digest
    expected_names = set(actual) - {"SHA256SUMS"}
    if set(entries) != expected_names or any(
        entries[name] != actual[name][1] for name in entries
    ):
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")


def _safe_archive_name(value: object) -> str:
    if type(value) is not str or not value or "\\" in value or len(value) > 1024:
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")
    candidate = value[:-1] if value.endswith("/") else value
    return _safe_manifest_path(candidate)


def _reserved_wrapper_path(value: str) -> bool:
    folded = value.casefold()
    first = folded.split("/", 1)[0]
    return (
        first == "assets"
        or first.startswith("appx")
        or folded == "[content_types].xml"
    )


def _safe_manifest_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or "\\" in value
        or ":" in value
        or len(value) > 1024
    ):
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 for character in value)
    ):
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")
    return value


def _zip_entry_bytes(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, maximum: int
) -> bytes:
    if info.file_size > maximum:
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")
    try:
        with archive.open(info) as handle:
            value = handle.read(maximum + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        raise StoreCandidateError(
            "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
        ) from None
    if len(value) != info.file_size or len(value) > maximum:
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")
    return value


def _zip_entry_sha256(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    size = 0
    try:
        with archive.open(info) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                if size > MAX_INNER_ENTRY_BYTES:
                    raise StoreCandidateError(
                        "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
                    )
                digest.update(chunk)
    except StoreCandidateError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile):
        raise StoreCandidateError(
            "STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID"
        ) from None
    if size != info.file_size:
        raise StoreCandidateError("STORE_CANDIDATE_PORTABLE_EVIDENCE_INVALID")
    return digest.hexdigest()


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


def _validate_external_license_shape(review: dict[str, Any]) -> None:
    if (
        set(review)
        != {
            "components",
            "reviewed_at",
            "reviewer",
            "sbom_sha256",
            "schema_version",
            "source_commit",
            "status",
        }
        or not _schema_is(review, "schema_version", 1)
        or review.get("status") != "approved"
        or not _lower_hex(review.get("source_commit"), 40)
        or not _lower_hex(review.get("sbom_sha256"), 64)
        or not _bounded_text(review.get("reviewer"))
        or not isinstance(review.get("components"), list)
        or not review["components"]
        or len(review["components"]) > MAX_MANIFEST_FILES
    ):
        raise StoreCandidateError("STORE_CANDIDATE_LICENSE_INPUT_INVALID")
    _utc_seconds(
        review.get("reviewed_at"), "STORE_CANDIDATE_LICENSE_INPUT_INVALID"
    )
    fields = {
        "evidence_url",
        "license_expression",
        "name",
        "redistribution",
        "version",
    }
    seen: set[tuple[str, str]] = set()
    for component in review["components"]:
        if not isinstance(component, dict) or set(component) != fields:
            raise StoreCandidateError("STORE_CANDIDATE_LICENSE_INPUT_INVALID")
        name = component.get("name")
        version = component.get("version")
        expression = component.get("license_expression")
        evidence_url = component.get("evidence_url")
        key = (name, version) if isinstance(name, str) and isinstance(version, str) else None
        if (
            key is None
            or key in seen
            or not _bounded_text(name)
            or not _bounded_text(version)
            or not _bounded_text(expression)
            or component.get("redistribution") != "approved"
            or type(evidence_url) is not str
            or not evidence_url.startswith("https://")
            or any(character.isspace() for character in evidence_url)
        ):
            raise StoreCandidateError("STORE_CANDIDATE_LICENSE_INPUT_INVALID")
        seen.add(key)


def _regular_local_file(value: str | Path, code: str) -> Path:
    path = Path(value)
    if (
        not path.is_absolute()
        or path.anchor.startswith("\\\\")
        or path.is_symlink()
        or _has_reparse_component(path)
    ):
        raise StoreCandidateError(code)
    try:
        resolved = path.resolve(strict=True)
        size = resolved.stat(follow_symlinks=False).st_size
    except (OSError, RuntimeError):
        raise StoreCandidateError(code) from None
    if not stat.S_ISREG(resolved.stat(follow_symlinks=False).st_mode) or size > MAX_JSON_BYTES:
        raise StoreCandidateError(code)
    return resolved


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
    total_size = 0
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
            or size > MAX_EVIDENCE_ROOT_BYTES
            or total_size > MAX_EVIDENCE_ROOT_BYTES - size
        ):
            raise StoreCandidateError(code)
        total_size += size
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


def _schema_is(value: dict[str, Any], key: str, expected: int) -> bool:
    return type(value.get(key)) is int and value[key] == expected


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
    mode.add_argument("--materialize-license-review", action="store_true")
    parser.add_argument("--repository-license-template", type=Path)
    args = parser.parse_args()
    try:
        if args.materialize_license_review:
            if args.repository_license_template is None:
                parser.error("repository license template is required")
            origin = materialize_license_review(
                args.evidence_root,
                args.repository_license_template,
                os.environ.get("APPROVED_LICENSE_REVIEW_BASE64", ""),
                expected_source_commit=args.expected_source_commit,
            )
            result: object = {
                "license_review_origin": origin,
                "status": "materialized",
            }
        elif args.create:
            result = create_candidate_evidence(
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
