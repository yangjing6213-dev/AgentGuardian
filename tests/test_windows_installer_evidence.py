from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
from dataclasses import replace
import subprocess
import sys

import pytest

from scripts.build_windows_portable import artifact_manifest, canonical_json_bytes
from scripts.verify_personal_release_profile import load_profile_snapshot


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "release_profiles" / "personal_exe_private_beta.json"
COMMIT = "a" * 40
BUILT_AT = "2026-08-21T00:00:00Z"
DEPENDENCIES = {"lock_sha256": "c" * 64, "versions": {"pyinstaller": "6.14.1"}}
README = (
    "AgentGuardian private beta is unsupported for unsupported or high-sensitivity data.\n"
    "Unsigned installer and Microsoft SmartScreen warnings are expected.\n"
    "Use manual installation and upgrade only; verify SHA256SUMS before running Setup.\n"
    "Uninstall offers a protected-state choice; user reports are preserved.\n"
    "Support and issue reports: https://github.com/yangjing6213-dev/AgentGuardian/issues\n"
    "Private Vulnerability Reporting is currently disabled.\n"
).encode("ascii")


def _verifier():
    return importlib.import_module("scripts.verify_windows_installer_candidate")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _checksums(root: Path) -> None:
    manifest = artifact_manifest(root)
    (root / "SHA256SUMS").write_bytes(
        "".join(
            f"{entry['sha256']} *{entry['path']}\n"
            for entry in manifest["files"]
            if entry["path"] != "SHA256SUMS"
        ).encode("ascii")
    )


def _payload_manifest(root: Path) -> dict[str, object]:
    names = ("AgentGuardian.cdx.json", "THIRD_PARTY_NOTICES.md")
    return {
        "algorithm": "sha256",
        "files": [
            {"path": name, "sha256": _sha256(root / name), "size": (root / name).stat().st_size}
            for name in names
        ],
        "schema": 1,
    }


def _refresh_payload_manifest(root: Path) -> None:
    (root / "PAYLOAD-MANIFEST.json").write_bytes(canonical_json_bytes(_payload_manifest(root)))


def _portable_bundle(tmp_path: Path, profile, *, dependencies=DEPENDENCIES) -> Path:
    bundle = tmp_path / "portable" / "AgentGuardian"
    (bundle / "_internal").mkdir(parents=True)
    (bundle / "AgentGuardian.exe").write_bytes(b"MZ-portable")
    (bundle / "_internal" / "runtime.bin").write_bytes(b"runtime")
    (bundle / "AgentGuardian.cdx.json").write_bytes(b'{"bomFormat":"CycloneDX"}\n')
    (bundle / "THIRD_PARTY_NOTICES.md").write_text("notices\n", encoding="ascii")
    (bundle / "PERSONAL-RELEASE-PROFILE.json").write_bytes(
        canonical_json_bytes(
            {
                "profile": "personal_exe_private_beta",
                "profile_sha256": profile.sha256,
                "schema": 2,
                "status": "pass",
            }
        )
    )
    (bundle / "BUILD-METADATA.json").write_bytes(
        canonical_json_bytes(
            {
                "artifact_status": "unsigned_development_only",
                "build_dependencies": dependencies,
                "build_mode": "pyinstaller_onedir",
                "built_at": BUILT_AT,
                "source_commit": COMMIT,
            }
        )
    )
    (bundle / "PAYLOAD-MANIFEST.json").write_bytes(
        canonical_json_bytes(artifact_manifest(bundle))
    )
    _checksums(bundle)
    return bundle


def _candidate_metadata(root: Path, profile) -> dict[str, object]:
    payload = root / "PAYLOAD-MANIFEST.json"
    installer = root / profile.profile["installer_filename"]
    portable_metadata = {
        "artifact_status": "unsigned_development_only",
        "build_dependencies": DEPENDENCIES,
        "build_mode": "pyinstaller_onedir",
        "built_at": BUILT_AT,
        "source_commit": COMMIT,
    }
    return {
        "architecture": profile.profile["architecture"],
        "artifact_status": "unsigned_private_beta",
        "build_dependencies": DEPENDENCIES,
        "built_at": BUILT_AT,
        "channel": profile.profile["channel"],
        "compiler_asset": profile.profile["inno_setup_asset"],
        "compiler_sha256": profile.profile["inno_setup_sha256"],
        "compiler_version": profile.profile["inno_setup_version"],
        "installer_filename": installer.name,
        "installer_sha256": _sha256(installer),
        "payload_manifest_sha256": _sha256(payload),
        "portable_artifact_status": "unsigned_development_only",
        "portable_build_mode": "pyinstaller_onedir",
        "portable_built_at": BUILT_AT,
        "portable_build_metadata_sha256": hashlib.sha256(canonical_json_bytes(portable_metadata)).hexdigest(),
        "portable_source_commit": COMMIT,
        "product_version": profile.profile["product_version"],
        "profile_sha256": profile.sha256,
        "schema": 1,
        "source_commit": COMMIT,
        "windows_file_version": profile.profile["windows_file_version"],
    }


def _write_candidate(root: Path, profile) -> None:
    root.mkdir()
    installer = root / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-synthetic-installer")
    (root / "AgentGuardian.cdx.json").write_bytes(b'{"bomFormat":"CycloneDX"}\n')
    (root / "THIRD_PARTY_NOTICES.md").write_text("notices\n", encoding="ascii")
    _refresh_payload_manifest(root)
    (root / "PRIVATE-BETA-README.txt").write_bytes(README)
    metadata = _candidate_metadata(root, profile)
    metadata_bytes = canonical_json_bytes(metadata)
    (root / "BUILD-METADATA.json").write_bytes(metadata_bytes)
    manifest = {**metadata, "build_metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest()}
    (root / "PRIVATE-BETA-MANIFEST.json").write_bytes(canonical_json_bytes(manifest))
    _checksums(root)


def _rebind_candidate(root: Path) -> None:
    metadata = json.loads((root / "BUILD-METADATA.json").read_text(encoding="ascii"))
    metadata["installer_sha256"] = _sha256(root / metadata["installer_filename"])
    metadata["payload_manifest_sha256"] = _sha256(root / "PAYLOAD-MANIFEST.json")
    metadata_bytes = canonical_json_bytes(metadata)
    (root / "BUILD-METADATA.json").write_bytes(metadata_bytes)
    (root / "PRIVATE-BETA-MANIFEST.json").write_bytes(
        canonical_json_bytes({**metadata, "build_metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest()})
    )
    _checksums(root)


@pytest.fixture
def candidate(tmp_path: Path) -> tuple[Path, object]:
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    root = tmp_path / "candidate"
    _write_candidate(root, profile)
    return root, profile


def _rewrite_json(path: Path, mutate) -> None:
    value = json.loads(path.read_text(encoding="ascii"))
    mutate(value)
    path.write_bytes(canonical_json_bytes(value))


def test_private_beta_manifest_binds_installer_to_payload_and_commit(candidate) -> None:
    root, profile = candidate

    assert _verifier().verify_candidate(root, COMMIT, profile) == {
        "channel": "personal_exe_private_beta",
        "status": "pass",
    }


def test_assembly_is_the_only_public_evidence_creation_path(tmp_path: Path) -> None:
    verifier = _verifier()
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    bundle = _portable_bundle(tmp_path, profile)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    evidence = tmp_path / "evidence"

    assert not hasattr(verifier, "write_candidate_evidence")
    assert builder.assemble_installer_evidence(
        installer, bundle, evidence, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile
    ) == evidence
    assert verifier.verify_candidate(evidence, COMMIT, profile)["status"] == "pass"
    assert not evidence.with_name("evidence.partial").exists()
    assert (evidence / "BUILD-METADATA.json").read_bytes()


def test_assemble_installer_evidence_verifies_portable_bundle_before_writing(tmp_path: Path) -> None:
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    bundle = _portable_bundle(tmp_path, profile)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    evidence = tmp_path / "evidence"

    assert builder.assemble_installer_evidence(
        installer, bundle, evidence, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile
    ) == evidence
    assert _verifier().verify_candidate(evidence, COMMIT, profile)["status"] == "pass"


def test_readme_has_required_private_beta_boundaries(tmp_path: Path) -> None:
    verifier = _verifier()
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    bundle = _portable_bundle(tmp_path, profile)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    evidence = builder.assemble_installer_evidence(
        installer, bundle, tmp_path / "evidence", source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile
    )
    readme = (evidence / "PRIVATE-BETA-README.txt").read_text(encoding="ascii")

    for marker in (
        "unsupported or high-sensitivity data",
        "Unsigned installer and Microsoft SmartScreen",
        "manual installation and upgrade",
        "SHA256SUMS",
        "protected-state choice",
        "reports are preserved",
        "https://github.com/yangjing6213-dev/AgentGuardian/issues",
        "Private Vulnerability Reporting is currently disabled",
    ):
        assert marker in readme


@pytest.mark.parametrize(
    ("target", "mutate", "code"),
    [
        ("installer", lambda root: (root / "AgentGuardian-Setup-0.2.0-beta.1-x64.exe").write_bytes(b"changed"), "CANDIDATE_INSTALLER_DIGEST_MISMATCH"),
        ("metadata", lambda root: _rewrite_json(root / "BUILD-METADATA.json", lambda value: value.__setitem__("payload_manifest_sha256", "b" * 64)), "CANDIDATE_PAYLOAD_DIGEST_MISMATCH"),
        ("metadata", lambda root: _rewrite_json(root / "BUILD-METADATA.json", lambda value: value.__setitem__("source_commit", "b" * 40)), "CANDIDATE_SOURCE_COMMIT_MISMATCH"),
        ("metadata", lambda root: _rewrite_json(root / "BUILD-METADATA.json", lambda value: value.__setitem__("product_version", "9.9.9")), "CANDIDATE_VERSION_MISMATCH"),
        ("metadata", lambda root: _rewrite_json(root / "BUILD-METADATA.json", lambda value: value.__setitem__("compiler_sha256", "b" * 64)), "CANDIDATE_COMPILER_DIGEST_MISMATCH"),
        ("metadata", lambda root: _rewrite_json(root / "BUILD-METADATA.json", lambda value: value.__setitem__("build_dependencies", {})), "CANDIDATE_PORTABLE_METADATA_MISMATCH"),
    ],
)
def test_candidate_rejects_metadata_binding_mutations(candidate, target, mutate, code) -> None:
    root, profile = candidate
    mutate(root)

    with pytest.raises(_verifier().CandidateEvidenceError, match=code):
        _verifier().verify_candidate(root, COMMIT, profile)


@pytest.mark.parametrize("key", ("source_commit", "installer_sha256", "payload_manifest_sha256", "build_dependencies"))
def test_candidate_rejects_manifest_binding_mutations(candidate, key: str) -> None:
    root, profile = candidate
    _rewrite_json(
        root / "PRIVATE-BETA-MANIFEST.json",
        lambda value: value.__setitem__(key, "b" * 40 if key == "source_commit" else ({} if key == "build_dependencies" else "b" * 64)),
    )

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_MANIFEST_BINDING_MISMATCH"):
        _verifier().verify_candidate(root, COMMIT, profile)


@pytest.mark.parametrize("filename", ("AgentGuardian.cdx.json", "THIRD_PARTY_NOTICES.md"))
def test_candidate_rejects_copied_payload_file_mutation_after_checksum_rebuild(candidate, filename: str) -> None:
    root, profile = candidate
    (root / filename).write_bytes(b"changed")
    _checksums(root)

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_PAYLOAD_ENTRY_MISMATCH"):
        _verifier().verify_candidate(root, COMMIT, profile)


def test_candidate_rejects_readme_mutation_after_checksum_rebuild(candidate) -> None:
    root, profile = candidate
    (root / "PRIVATE-BETA-README.txt").write_bytes(b"changed\n")
    _checksums(root)

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_README_INVALID"):
        _verifier().verify_candidate(root, COMMIT, profile)


def test_candidate_rejects_empty_installer(candidate) -> None:
    root, profile = candidate
    (root / profile.profile["installer_filename"]).write_bytes(b"")
    _rebind_candidate(root)

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_INSTALLER_INVALID"):
        _verifier().verify_candidate(root, COMMIT, profile)


def test_candidate_rejects_noncanonical_sbom_after_complete_rebind(candidate) -> None:
    root, profile = candidate
    (root / "AgentGuardian.cdx.json").write_bytes(b'{ "bomFormat": "CycloneDX" }\n')
    _refresh_payload_manifest(root)
    _rebind_candidate(root)

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_SBOM_INVALID"):
        _verifier().verify_candidate(root, COMMIT, profile)


def test_candidate_rejects_absolute_payload_path_after_complete_rebind(candidate) -> None:
    root, profile = candidate
    payload = json.loads((root / "PAYLOAD-MANIFEST.json").read_text(encoding="ascii"))
    payload["files"][0]["path"] = "C:/absolute.json"
    (root / "PAYLOAD-MANIFEST.json").write_bytes(canonical_json_bytes(payload))
    _rebind_candidate(root)

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_PAYLOAD_MANIFEST_INVALID"):
        _verifier().verify_candidate(root, COMMIT, profile)


@pytest.mark.parametrize(
    ("field", "value"),
    (("inno_setup_sha256", "invalid"), ("architecture", 64), ("installer_filename", 1), ("inno_setup_asset", "C:/Users/test.exe")),
)
def test_candidate_rejects_malformed_profile_snapshot(candidate, field: str, value: object) -> None:
    root, profile = candidate
    malformed = replace(profile, profile={**profile.profile, field: value})

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_PROFILE_INVALID"):
        _verifier().verify_candidate(root, COMMIT, malformed)


def test_cli_maps_profile_loading_failure_to_fixed_public_code(tmp_path: Path) -> None:
    missing = tmp_path / "missing-profile.json"
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/verify_windows_installer_candidate.py",
            "--evidence-root",
            str(tmp_path),
            "--expected-commit",
            COMMIT,
            "--profile",
            str(missing),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "CANDIDATE_PROFILE_INVALID" in completed.stderr
    assert "Traceback" not in completed.stderr
    assert str(tmp_path) not in completed.stderr


@pytest.mark.parametrize(
    ("target_name", "code"),
    [
        ("evidence-parent", "CANDIDATE_OUTPUT_INVALID"),
        ("installer", "CANDIDATE_INSTALLER_INVALID"),
        ("portable-root", "CANDIDATE_PAYLOAD_INVALID"),
        ("copied-source", "CANDIDATE_PAYLOAD_INVALID"),
    ],
)
def test_writer_rejects_reparse_path_components(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_name: str, code: str) -> None:
    verifier = _verifier()
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    bundle = _portable_bundle(tmp_path, profile)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    evidence = tmp_path / "evidence"
    target = {
        "evidence-parent": evidence.parent,
        "installer": installer,
        "portable-root": bundle,
        "copied-source": bundle / "THIRD_PARTY_NOTICES.md",
    }[target_name]
    real = verifier._has_reparse_component
    monkeypatch.setattr(verifier, "_has_reparse_component", lambda path: Path(path) == target or real(path))

    with pytest.raises(verifier.CandidateEvidenceError, match=code):
        builder.assemble_installer_evidence(evidence_root=evidence, installer=installer, bundle_root=bundle, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile)
    assert not evidence.exists()


def test_writer_leaves_no_candidate_root_when_copy_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = _verifier()
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    bundle = _portable_bundle(tmp_path, profile)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    evidence = tmp_path / "evidence"
    with monkeypatch.context() as patch:
        patch.setattr(verifier.shutil, "copyfile", lambda *_args: (_ for _ in ()).throw(OSError()))
        with pytest.raises(verifier.CandidateEvidenceError, match="CANDIDATE_OUTPUT_INVALID"):
            builder.assemble_installer_evidence(evidence_root=evidence, installer=installer, bundle_root=bundle, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile)
    assert not evidence.exists()
    assert not evidence.with_name("evidence.partial").exists()
    assert builder.assemble_installer_evidence(evidence_root=evidence, installer=installer, bundle_root=bundle, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile) == evidence


def test_writer_never_removes_partial_created_by_another_assembly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = _verifier()
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    bundle = _portable_bundle(tmp_path, profile)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    evidence = tmp_path / "evidence"
    partial = tmp_path / "evidence.partial"
    marker = partial / "owned-by-other"
    real_mkdir = Path.mkdir

    def create_by_other(path: Path, *args, **kwargs) -> None:
        if path == partial:
            real_mkdir(path)
            marker.write_text("marker", encoding="ascii")
            raise FileExistsError()
        real_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", create_by_other)

    with pytest.raises(verifier.CandidateEvidenceError, match="CANDIDATE_OUTPUT_INVALID"):
        builder.assemble_installer_evidence(evidence_root=evidence, installer=installer, bundle_root=bundle, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile)
    assert not evidence.exists()
    assert marker.read_text(encoding="ascii") == "marker"


@pytest.mark.parametrize("overlap", ("equal", "descendant", "installer"))
def test_writer_rejects_output_overlap_with_verified_inputs(tmp_path: Path, overlap: str) -> None:
    verifier = _verifier()
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    bundle = _portable_bundle(tmp_path, profile)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    evidence = {
        "equal": bundle,
        "descendant": bundle / "evidence",
        "installer": installer,
    }[overlap]
    partial = evidence.with_name(evidence.name + ".partial")

    with pytest.raises(verifier.CandidateEvidenceError, match="CANDIDATE_OUTPUT_INVALID"):
        builder.assemble_installer_evidence(evidence_root=evidence, installer=installer, bundle_root=bundle, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile)
    assert not partial.exists()
    if overlap == "descendant":
        assert not evidence.exists()


def test_assembler_rejects_output_descendant_of_verified_portable_bundle(tmp_path: Path) -> None:
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    bundle = _portable_bundle(tmp_path, profile)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    evidence = bundle / "evidence"
    partial = bundle / "evidence.partial"

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_OUTPUT_INVALID"):
        builder.assemble_installer_evidence(installer, bundle, evidence, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile)
    assert not evidence.exists()
    assert not partial.exists()


@pytest.mark.parametrize("alias_kind", ("portable", "evidence"))
def test_writer_rejects_lexical_alias_overlap_with_portable_bundle(tmp_path: Path, alias_kind: str) -> None:
    verifier = _verifier()
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    bundle = _portable_bundle(tmp_path, profile)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    portable = bundle / ".." / bundle.name if alias_kind == "portable" else bundle
    evidence = bundle / "evidence" if alias_kind == "portable" else bundle / ".." / bundle.name / "evidence"
    partial = evidence.with_name(evidence.name + ".partial")

    with pytest.raises(verifier.CandidateEvidenceError, match="CANDIDATE_OUTPUT_INVALID"):
        builder.assemble_installer_evidence(evidence_root=evidence, installer=installer, bundle_root=portable, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile)
    assert not evidence.exists()
    assert not partial.exists()


@pytest.mark.parametrize("version", ("C:/Users/test", "bad\\path"))
def test_writer_rejects_path_like_portable_dependency_values(tmp_path: Path, version: str) -> None:
    verifier = _verifier()
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    dependencies = {"lock_sha256": "c" * 64, "versions": {"pyinstaller": version}}
    bundle = _portable_bundle(tmp_path, profile, dependencies=dependencies)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    evidence = tmp_path / "evidence"
    partial = tmp_path / "evidence.partial"

    with pytest.raises(verifier.CandidateEvidenceError, match="CANDIDATE_PORTABLE_METADATA_MISMATCH"):
        builder.assemble_installer_evidence(evidence_root=evidence, installer=installer, bundle_root=bundle, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile)
    assert not evidence.exists()
    assert not partial.exists()


@pytest.mark.parametrize(
    "rebound",
    (
        {"lock_sha256": "d" * 64, "versions": {}},
        {"lock_sha256": "d" * 64, "versions": {"pyinstaller": "6.15.0"}},
    ),
)
def test_candidate_rejects_rebound_dependency_snapshot_against_verified_portable(candidate, tmp_path: Path, rebound: dict[str, object]) -> None:
    root, profile = candidate
    bundle = _portable_bundle(tmp_path, profile)
    trusted = json.loads((bundle / "BUILD-METADATA.json").read_text(encoding="ascii"))
    _rewrite_json(root / "BUILD-METADATA.json", lambda value: value.__setitem__("build_dependencies", rebound))
    _rewrite_json(
        root / "BUILD-METADATA.json",
        lambda value: value.__setitem__(
            "portable_build_metadata_sha256",
            hashlib.sha256(
                canonical_json_bytes(
                    {
                        "artifact_status": value["portable_artifact_status"],
                        "build_dependencies": value["build_dependencies"],
                        "build_mode": value["portable_build_mode"],
                        "built_at": value["portable_built_at"],
                        "source_commit": value["portable_source_commit"],
                    }
                )
            ).hexdigest(),
        ),
    )
    _rebind_candidate(root)

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_PORTABLE_METADATA_MISMATCH"):
        _verifier().verify_candidate(root, COMMIT, profile, expected_portable_metadata=trusted)


def test_assembly_rejects_dangling_destination_link(tmp_path: Path) -> None:
    verifier = _verifier()
    builder = importlib.import_module("scripts.build_windows_installer")
    profile = load_profile_snapshot(ROOT, PROFILE_PATH)
    bundle = _portable_bundle(tmp_path, profile)
    installer = tmp_path / profile.profile["installer_filename"]
    installer.write_bytes(b"MZ-installer")
    evidence = tmp_path / "evidence"
    try:
        os.symlink(tmp_path / "missing-target", evidence, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(verifier.CandidateEvidenceError, match="CANDIDATE_OUTPUT_INVALID"):
        builder.assemble_installer_evidence(evidence_root=evidence, installer=installer, bundle_root=bundle, source_commit=COMMIT, built_at=BUILT_AT, profile_snapshot=profile)
    assert evidence.is_symlink()
    assert not evidence.with_name("evidence.partial").exists()


def test_candidate_rejects_oversized_json_document(candidate, monkeypatch: pytest.MonkeyPatch) -> None:
    root, profile = candidate
    verifier = _verifier()
    monkeypatch.setattr(verifier, "MAX_METADATA_BYTES", 8, raising=False)

    with pytest.raises(verifier.CandidateEvidenceError, match="CANDIDATE_JSON_INVALID"):
        verifier.verify_candidate(root, COMMIT, profile)


def test_payload_manifest_limit_matches_task3_and_metadata_remains_smaller(candidate, monkeypatch: pytest.MonkeyPatch) -> None:
    root, _profile = candidate
    verifier = _verifier()
    builder = importlib.import_module("scripts.build_windows_installer")
    calls: list[tuple[Path, int]] = []
    original = verifier._json

    def record_limit(path: Path, limit: int):
        calls.append((path, limit))
        return original(path, limit)

    monkeypatch.setattr(verifier, "_json", record_limit)

    verifier._payload_manifest(root)

    assert verifier.MAX_PAYLOAD_MANIFEST_BYTES == builder.MAX_MANIFEST_BYTES == 8 * 1024 * 1024
    assert verifier.MAX_METADATA_BYTES < verifier.MAX_PAYLOAD_MANIFEST_BYTES
    assert verifier.MAX_SBOM_BYTES < verifier.MAX_PAYLOAD_MANIFEST_BYTES
    assert calls == [(root / "PAYLOAD-MANIFEST.json", verifier.MAX_PAYLOAD_MANIFEST_BYTES)]


def test_cli_maps_deep_json_to_fixed_code_without_traceback(candidate) -> None:
    root, _profile = candidate
    (root / "PAYLOAD-MANIFEST.json").write_bytes(b'{"x":' * 2000 + b"0" + b"}" * 2000)
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/verify_windows_installer_candidate.py",
            "--evidence-root",
            str(root),
            "--expected-commit",
            COMMIT,
            "--profile",
            str(PROFILE_PATH),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "CANDIDATE_PAYLOAD_MANIFEST_INVALID" in completed.stderr
    assert "Traceback" not in completed.stderr
    assert str(root) not in completed.stderr


def test_candidate_rejects_duplicate_json_keys(candidate) -> None:
    root, profile = candidate
    (root / "BUILD-METADATA.json").write_bytes(b'{"schema":1,"schema":1}\n')

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_JSON_INVALID"):
        _verifier().verify_candidate(root, COMMIT, profile)


@pytest.mark.parametrize("filename", ("unexpected.txt", "AgentGuardian.cdx.json"))
def test_candidate_rejects_extra_or_missing_files(candidate, filename: str) -> None:
    root, profile = candidate
    path = root / filename
    if path.exists():
        path.unlink()
    else:
        path.write_bytes(b"unexpected")

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_FILE_SET_INVALID"):
        _verifier().verify_candidate(root, COMMIT, profile)


def test_candidate_rejects_oversized_file(candidate, monkeypatch: pytest.MonkeyPatch) -> None:
    root, profile = candidate
    verifier = _verifier()
    monkeypatch.setattr(verifier, "MAX_ARTIFACT_BYTES", 8)

    with pytest.raises(verifier.CandidateEvidenceError, match="CANDIDATE_FILE_SIZE_INVALID"):
        verifier.verify_candidate(root, COMMIT, profile)


def test_candidate_rejects_reparse_point(candidate, monkeypatch: pytest.MonkeyPatch) -> None:
    root, profile = candidate
    verifier = _verifier()
    monkeypatch.setattr(verifier, "_has_reparse_component", lambda path: Path(path).name == "PRIVATE-BETA-README.txt")

    with pytest.raises(verifier.CandidateEvidenceError, match="CANDIDATE_REPARSE_POINT"):
        verifier.verify_candidate(root, COMMIT, profile)


def test_candidate_rejects_absolute_artifact_path(candidate) -> None:
    root, profile = candidate
    _rewrite_json(root / "BUILD-METADATA.json", lambda value: value.__setitem__("installer_filename", "C:/Users/test/setup.exe"))

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_METADATA_INVALID"):
        _verifier().verify_candidate(root, COMMIT, profile)


def test_candidate_rejects_noncanonical_json(candidate) -> None:
    root, profile = candidate
    (root / "PRIVATE-BETA-MANIFEST.json").write_bytes(b'{ "schema": 1 }\n')

    with pytest.raises(_verifier().CandidateEvidenceError, match="CANDIDATE_JSON_INVALID"):
        _verifier().verify_candidate(root, COMMIT, profile)
