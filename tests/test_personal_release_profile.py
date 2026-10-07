from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import subprocess
import sys
import time
import tomllib
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_BETA_PROFILE_PATH = (
    ROOT / "release_profiles" / "personal_exe_private_beta.json"
)
PROFILE_PATH = PRIVATE_BETA_PROFILE_PATH
SECURITY_DOCS = ROOT / "docs" / "security"
ACTIVE_PERSONAL_DOCS = (
    ROOT / "README.md",
    ROOT / "docs" / "architecture.md",
    SECURITY_DOCS / "personal-v1-threat-model.md",
    SECURITY_DOCS / "personal-v1-privacy.md",
    SECURITY_DOCS / "personal-v1-support.md",
    SECURITY_DOCS / "personal-v1-release-runbook.md",
    SECURITY_DOCS / "personal-v1-independent-machine-acceptance.md",
)
GOVERNING_PERSONAL_DOCS = (
    ROOT
    / "docs"
    / "superpowers"
    / "specs"
    / "2026-08-16-agentguardian-personal-v1-design.md",
    ROOT
    / "docs"
    / "superpowers"
    / "plans"
    / "2026-08-21-agentguardian-personal-exe-private-beta.md",
)
HISTORICAL_SECURITY_DOCS = (
    SECURITY_DOCS / "windows-mvp-threat-model.md",
    SECURITY_DOCS / "windows-release-evidence.md",
)
ACTIVE_INTEGRATIONS_PREVIEW_DOC = SECURITY_DOCS / "integrations-preview.md"
PRIVATE_BETA_STATUS_PATH = (
    SECURITY_DOCS / "personal-exe-private-beta-status.json"
)
PRIVATE_BETA_EVIDENCE_PATH = (
    SECURITY_DOCS
    / "evidence"
    / "8ad46e31486d05a2b4572ef8bd7442eb22a7b5b6-gates.json"
)
PRIVATE_BETA_GITLEAKS_CONFIG_PATH = (
    SECURITY_DOCS
    / "evidence"
    / "8ad46e31486d05a2b4572ef8bd7442eb22a7b5b6-gitleaks.toml"
)
PRIVATE_BETA_LOCAL_EVIDENCE_PATH = (
    SECURITY_DOCS
    / "evidence"
    / "8ad46e31486d05a2b4572ef8bd7442eb22a7b5b6-local.json"
)
PRIVATE_BETA_PRIVACY_EVIDENCE_PATH = (
    SECURITY_DOCS
    / "evidence"
    / "8ad46e31486d05a2b4572ef8bd7442eb22a7b5b6-privacy.json"
)
FROZEN_PRIVATE_BETA_COMMIT = "8ad46e31486d05a2b4572ef8bd7442eb22a7b5b6"
_MACHINE_SPECIFIC_ABSOLUTE_PATH = re.compile(
    r"(?i)(?:\b[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+)"
)
_PREMATURE_RELEASE_CLAIMS = (
    "Production safety is established",
    "is production safe",
    "WACK has passed",
    "WACK gate passed",
    "Store release is approved",
    "Store gate passed",
    "license and Qt approval has passed",
    "license gate passed",
    "clean-machine acceptance has passed",
    "independent-machine gate passed",
    "all eight gates have passed",
    "eight-gate decision is GO",
    "formal personal release",
    "已通过生产安全验证",
    "WACK 已通过",
    "Store 发布已批准",
    "许可证和 Qt 审查已批准",
    "干净机器验收已通过",
    "八项门禁已全部通过",
    "正式个人版发布",
)
_PRIVATE_BETA_GATE_NAMES = (
    "scope",
    "local",
    "remote",
    "supply_chain",
    "installer",
    "independent_machine",
    "independent_review",
    "operations",
)


def _assert_no_machine_specific_paths(text: str) -> None:
    assert _MACHINE_SPECIFIC_ABSOLUTE_PATH.search(text) is None, (
        "active Personal v1 document contains machine-specific path"
    )


def _assert_no_premature_release_claims(text: str) -> None:
    normalized = " ".join(text.casefold().split())
    for claim in _PREMATURE_RELEASE_CLAIMS:
        normalized_claim = " ".join(claim.casefold().split())
        assert normalized_claim not in normalized, (
            f"active Personal v1 document contains premature claim: {claim}"
        )


def _verifier():
    try:
        return importlib.import_module("scripts.verify_personal_release_profile")
    except ModuleNotFoundError:
        pytest.fail("personal release profile verifier is missing")


def _profile() -> dict[str, object]:
    if not PROFILE_PATH.is_file():
        pytest.fail("personal release profile is missing")
    return json.loads(PROFILE_PATH.read_text(encoding="ascii"))


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def test_private_beta_identity_is_frozen() -> None:
    verifier = _verifier()
    profile = json.loads(PRIVATE_BETA_PROFILE_PATH.read_text(encoding="ascii"))

    assert PRIVATE_BETA_PROFILE_PATH.read_bytes() == _canonical(profile)
    assert profile["schema"] == 2
    assert profile["name"] == "personal_exe_private_beta"
    assert profile["channel"] == "personal_exe_private_beta"
    assert profile["product_version"] == "0.2.0-beta.1"
    assert profile["python_package_version"] == "0.2.0b1"
    assert profile["windows_file_version"] == "0.2.0.1"
    assert profile["architecture"] == "x64"
    assert profile["installer_app_id"] == "{7A76221A-CFA0-4860-B250-7083B736F3FB}"
    assert profile["installer_filename"] == (
        "AgentGuardian-Setup-0.2.0-beta.1-x64.exe"
    )
    assert profile["install_directory"] == (
        r"{localappdata}\Programs\AgentGuardian"
    )
    assert profile["inno_setup_version"] == "7.0.2"
    assert profile["inno_setup_release_tag"] == "is-7_0_2"
    assert profile["inno_setup_asset"] == "innosetup-7.0.2-x64.exe"
    assert profile["inno_setup_sha256"] == (
        "5ad54ca3def786f8f4212552e54cc6d8d61329e2d24a1cfee0571d42c2684ff1"
    )
    assert profile["inno_setup_iscc_sha256"] == (
        "0ff6140d641f84b64204a2c4d52207c6fc437c9f4db8779c83083d84f7e3d70d"
    )
    assert profile["package_input_paths"] == sorted(
        profile["package_input_paths"]
    )
    snapshot = verifier.load_profile_snapshot(ROOT, PRIVATE_BETA_PROFILE_PATH)
    assert verifier.verify_profile(ROOT, snapshot) == {
        "profile": "personal_exe_private_beta",
        "status": "pass",
    }


def test_private_beta_version_documents_remain_frozen() -> None:
    profile = json.loads(PRIVATE_BETA_PROFILE_PATH.read_text(encoding="ascii"))
    for relative in (
        "docs/superpowers/specs/2026-08-16-agentguardian-personal-v1-design.md",
        "docs/superpowers/specs/2026-08-21-agentguardian-personal-exe-private-beta-design.md",
    ):
        specification = (ROOT / relative).read_text(encoding="utf-8")
        assert profile["product_version"] in specification
        assert "`0.1.0` candidate" not in specification


def test_private_beta_workflow_is_exact_sha_read_only_and_nonpublishing() -> None:
    path = ROOT / ".github" / "workflows" / "windows-exe-private-beta.yml"
    if not path.is_file():
        pytest.fail("Windows EXE private-beta workflow is missing")
    workflow = path.read_text(encoding="utf-8")
    folded = workflow.casefold()

    assert "permissions:\n  contents: read" in workflow
    assert "push:\n    branches:\n      - agent/founder-alpha" in workflow
    assert "ref: ${{ env.EXPECTED_SOURCE_COMMIT }}" in workflow
    assert (
        "EXPECTED_SOURCE_COMMIT: ${{ github.event_name == 'workflow_dispatch' "
        "&& inputs.candidate_sha || github.sha }}"
    ) in workflow
    assert "WORKFLOW_SOURCE_COMMIT: ${{ github.workflow_sha }}" in workflow
    assert "$env:WORKFLOW_SOURCE_COMMIT -cne $env:EXPECTED_SOURCE_COMMIT" in workflow
    assert "git rev-parse HEAD" in workflow
    assert "git status --porcelain=v1 --untracked-files=all" in workflow
    assert "--require-hashes -r requirements-dev.lock" in workflow
    assert "--require-hashes -r requirements-build.lock" in workflow
    assert "python -m pytest -q -p no:cacheprovider" in workflow
    assert "personal_exe_private_beta.json" in workflow
    assert "--release-profile personal_exe_private_beta" in workflow
    assert "--artifact-status unsigned_development_only" in workflow
    assert "DriveType -ne 3" in workflow
    assert workflow.count("permissions:") == 1
    assert "contents: write" not in folded
    assert "public repository artifact" in folded
    for forbidden in (
        "gh release create",
        "git tag",
        "git push",
        "pages",
        "deployment",
        "store submission",
    ):
        assert forbidden not in folded


def test_active_tree_has_only_exe_private_beta_delivery() -> None:
    for relative in (
        ".github/workflows/windows-mvp.yml",
        ".github/workflows/windows-store-candidate.yml",
        "release_profiles/personal_store_release.json",
        "scripts/build_windows_msix.py",
        "scripts/verify_windows_msix.ps1",
        "scripts/verify_wack_report.py",
        "scripts/verify_windows_release_candidate.py",
        "scripts/verify_windows_store_candidate.py",
        "tests/fixtures/wack/README.md",
    ):
        assert not (ROOT / relative).exists()

    assert (ROOT / ".github/workflows/windows-exe-private-beta.yml").is_file()
    assert (ROOT / "release_profiles/personal_exe_private_beta.json").is_file()

    profile = json.loads(PRIVATE_BETA_PROFILE_PATH.read_text(encoding="ascii"))
    assert ".github/workflows/windows-exe-private-beta.yml" in profile[
        "required_source_paths"
    ]
    assert ".github/workflows/windows-mvp.yml" not in profile[
        "required_source_paths"
    ]

    verifier_source = (ROOT / "scripts/verify_personal_release_profile.py").read_text(
        encoding="utf-8"
    )
    portable_source = (ROOT / "scripts/build_windows_portable.py").read_text(
        encoding="utf-8"
    )
    assert "personal_store_release" not in verifier_source
    assert "personal_store_release" not in portable_source

    active_spec = (
        ROOT
        / "docs/superpowers/specs/2026-08-16-agentguardian-personal-v1-design.md"
    ).read_text(encoding="utf-8")
    for retired_route in (
        "personal_store_release",
        "Microsoft Store MSIX",
        "Store metadata",
        "Store-candidate workflow",
        "Windows App Certification Kit",
        "private-audience Store package",
        "manual Windows EXE workflow",
    ):
        assert retired_route not in " ".join(active_spec.split())

    active_plan = (
        ROOT
        / "docs/superpowers/plans/2026-08-21-agentguardian-personal-exe-private-beta.md"
    ).read_text(encoding="utf-8")
    active_design = (
        ROOT
        / "docs/superpowers/specs/2026-08-21-agentguardian-personal-exe-private-beta-design.md"
    ).read_text(encoding="utf-8")
    for document in (active_plan, active_design):
        assert "not an access-controlled distribution channel" in " ".join(
            document.split()
        )
    assert "artifact remains unsigned and private" not in active_plan.casefold()


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        (lambda value: value.update({"unexpected": "value"}), "PROFILE_SCHEMA_INVALID"),
        (
            lambda value: value.update({"installer_app_id": "{changed}"}),
            "PROFILE_IDENTITY_INVALID",
        ),
        (
            lambda value: value.update({"product_version": "0.2.0"}),
            "PROFILE_IDENTITY_INVALID",
        ),
        (
            lambda value: value.update({"package_input_paths": ["../outside"]}),
            "PROFILE_PATH_INVALID",
        ),
        (
            lambda value: value.update(
                {"package_input_paths": ["src/agentguardian", "LICENSE"]}
            ),
            "PROFILE_ARRAY_INVALID",
        ),
    ),
)
def test_private_beta_profile_rejects_schema_and_identity_mutations(
    mutation, code: str
) -> None:
    verifier = _verifier()
    profile = json.loads(PRIVATE_BETA_PROFILE_PATH.read_text(encoding="ascii"))
    mutation(profile)

    with pytest.raises(verifier.ProfileViolation, match=f"^{code}$"):
        verifier.profile_snapshot_from_bytes(_canonical(profile))


def _passing_private_beta_status() -> dict[str, object]:
    status = json.loads(PRIVATE_BETA_STATUS_PATH.read_text(encoding="ascii"))
    status["candidate_commit"] = "a" * 40
    status["private_beta_decision"] = "PRIVATE-BETA-READY"
    for gate in status["gates"]:
        gate.update(
            {
                "evidence_sha256": "b" * 64,
                "source_commit": "a" * 40,
                "status": "pass",
                "verified_at": "2026-08-21T00:00:00Z",
            }
        )
    return status


def test_private_beta_status_binds_partial_evidence_to_frozen_candidate() -> None:
    verifier = _verifier()
    status = json.loads(PRIVATE_BETA_STATUS_PATH.read_text(encoding="ascii"))
    evidence_raw = PRIVATE_BETA_EVIDENCE_PATH.read_bytes()
    evidence = json.loads(evidence_raw.decode("ascii"))
    evidence_sha256 = hashlib.sha256(evidence_raw).hexdigest()
    local_raw = PRIVATE_BETA_LOCAL_EVIDENCE_PATH.read_bytes()
    local_evidence = json.loads(local_raw.decode("ascii"))
    local_sha256 = hashlib.sha256(local_raw).hexdigest()
    privacy_raw = PRIVATE_BETA_PRIVACY_EVIDENCE_PATH.read_bytes()
    privacy_evidence = json.loads(privacy_raw.decode("ascii"))
    gitleaks_config_raw = PRIVATE_BETA_GITLEAKS_CONFIG_PATH.read_bytes()

    assert PRIVATE_BETA_STATUS_PATH.read_bytes() == _canonical(status)
    assert evidence_raw == _canonical(evidence)
    assert local_raw == _canonical(local_evidence)
    assert privacy_raw == _canonical(privacy_evidence)
    assert privacy_evidence["passed"] is True
    assert hashlib.sha256(privacy_raw).hexdigest() == (
        local_evidence["results"]["privacy_acceptance"]["evidence_sha256"]
    )
    assert hashlib.sha256(gitleaks_config_raw).hexdigest() == (
        local_evidence["results"]["secret_scan"]["config_sha256"]
    )
    assert evidence == {
        "candidate_commit": FROZEN_PRIVATE_BETA_COMMIT,
        "gates_supported": [
            "scope",
            "remote",
            "installer",
            "independent_review",
        ],
        "github": {
            "artifact_digest": (
                "sha256:72cec5e1140be4dbbac48d6cd629a648605197ce9be0e2def99dae00a831d3bf"
            ),
            "artifact_id": 9443863074,
            "artifact_name": (
                "agentguardian-personal-exe-candidate-"
                f"{FROZEN_PRIVATE_BETA_COMMIT}"
            ),
            "runs": [
                {
                    "conclusion": "success",
                    "event": "push",
                    "id": 32474453589,
                    "workflow": "windows-exe-private-beta",
                },
                {
                    "conclusion": "success",
                    "event": "push",
                    "id": 32474453768,
                    "workflow": "CI",
                },
                {
                    "conclusion": "success",
                    "event": "pull_request",
                    "id": 32474456582,
                    "workflow": "CI",
                },
            ],
        },
        "independent_review": {
            "agent_id": "01a02362-a90e-7b00-a999-90ff7f8fc956",
            "content_match": True,
            "critical_count": 0,
            "decision": "APPROVED",
            "focused_tests": {"passed": 258, "skipped": 3},
            "important_count": 0,
            "lower_findings": [],
            "privacy_boundary_tests": {"passed": 16, "skipped": 1},
        },
        "limitations": [
            "local secret-scan evidence is not recorded",
            "external license and Qt approval is not recorded",
            "two-machine acceptance is not recorded",
            "private security intake and operations readiness are not recorded",
        ],
        "recorded_at": "2026-08-21T11:01:11Z",
        "schema": 1,
        "verification": {
            "candidate_evidence": "pass",
            "profile": "pass",
            "source_policy": "pass",
        },
    }
    assert local_evidence == {
        "candidate_commit": FROZEN_PRIVATE_BETA_COMMIT,
        "environment": {
            "architecture": "amd64",
            "os_build": "10.0.26200",
            "python": "3.12.2",
        },
        "gates_supported": ["local"],
        "limitations": [
            "developer-machine evidence is not independent-machine acceptance",
            (
                "Gitleaks used the reviewed external evidence configuration rather "
                "than a candidate package input"
            ),
        ],
        "recorded_at": "2026-08-21T12:10:10Z",
        "repository_state": {
            "observed_head_commit": FROZEN_PRIVATE_BETA_COMMIT,
            "status_porcelain_v2_after": [],
            "status_porcelain_v2_before": [],
            "worktree_mode": "detached",
        },
        "results": {
            "brand": "pass",
            "compileall": "pass",
            "diff_check": "pass",
            "full_tests": {"passed": 1834, "skipped": 17, "warnings": 0},
            "installer_tests": "pass within full suite",
            "privacy_acceptance": {
                "evidence_sha256": (
                    "946013ed1e01168e52ac839972811f0fcbc697d2c0c2eb7439bdb0dd3065522d"
                ),
                "status": "pass",
            },
            "profile": "pass",
            "secret_scan": {
                "commits_scanned": 296,
                "config_sha256": (
                    "2f90f52394b66537984edc94370a907bf700fdf74aa0a892edd165abc3357113"
                ),
                "findings": 0,
                "gitleaks_version": "8.30.1",
                "log_opts": "--all -m",
                "scope": "repository history, all refs, merge-aware",
            },
            "worktree": "clean",
        },
        "schema": 1,
    }
    assert status["candidate_commit"] == FROZEN_PRIVATE_BETA_COMMIT
    assert status["formal_release_decision"] == "NO-GO"
    assert status["private_beta_decision"] == "PRIVATE-BETA-NOT-READY"
    assert [gate["name"] for gate in status["gates"]] == list(
        _PRIVATE_BETA_GATE_NAMES
    )
    passed = {
        "scope": (evidence_sha256, "2026-08-21T11:01:11Z"),
        "local": (local_sha256, "2026-08-21T12:10:10Z"),
        "remote": (evidence_sha256, "2026-08-21T11:01:11Z"),
        "installer": (evidence_sha256, "2026-08-21T11:01:11Z"),
        "independent_review": (evidence_sha256, "2026-08-21T11:01:11Z"),
    }
    for gate in status["gates"]:
        if gate["name"] in passed:
            digest, verified_at = passed[gate["name"]]
            assert gate == {
                "evidence_sha256": digest,
                "name": gate["name"],
                "source_commit": FROZEN_PRIVATE_BETA_COMMIT,
                "status": "pass",
                "verified_at": verified_at,
            }
        else:
            assert gate == {
                "evidence_sha256": None,
                "name": gate["name"],
                "source_commit": None,
                "status": "pending",
                "verified_at": None,
            }
    snapshot = verifier.load_private_beta_status_snapshot(
        ROOT, PRIVATE_BETA_STATUS_PATH
    )
    assert verifier.verify_private_beta_status(snapshot) == {
        "formal_release": "NO-GO",
        "private_beta": "PRIVATE-BETA-NOT-READY",
        "status": "pass",
    }


def test_private_beta_status_rejects_cross_candidate_evidence() -> None:
    verifier = _verifier()
    ready = _passing_private_beta_status()
    ready["gates"][0]["source_commit"] = "c" * 40

    with pytest.raises(verifier.ProfileViolation, match="^STATUS_GATE_INVALID$"):
        verifier.private_beta_status_snapshot_from_bytes(_canonical(ready))


def test_private_beta_status_cannot_change_formal_release_decision() -> None:
    verifier = _verifier()
    status = json.loads(PRIVATE_BETA_STATUS_PATH.read_text(encoding="ascii"))
    status["formal_release_decision"] = "GO"

    with pytest.raises(verifier.ProfileViolation, match="^STATUS_DECISION_INVALID$"):
        verifier.private_beta_status_snapshot_from_bytes(_canonical(status))


@pytest.mark.parametrize("pending_gate", _PRIVATE_BETA_GATE_NAMES)
def test_private_beta_ready_requires_every_gate_for_one_candidate(
    pending_gate: str,
) -> None:
    verifier = _verifier()
    ready = _passing_private_beta_status()
    snapshot = verifier.private_beta_status_snapshot_from_bytes(_canonical(ready))
    assert verifier.verify_private_beta_status(snapshot)["private_beta"] == (
        "PRIVATE-BETA-READY"
    )

    gate = next(item for item in ready["gates"] if item["name"] == pending_gate)
    gate.update(
        {
            "evidence_sha256": None,
            "source_commit": None,
            "status": "pending",
            "verified_at": None,
        }
    )
    ready["private_beta_decision"] = "PRIVATE-BETA-NOT-READY"
    snapshot = verifier.private_beta_status_snapshot_from_bytes(_canonical(ready))
    assert verifier.verify_private_beta_status(snapshot)["private_beta"] == (
        "PRIVATE-BETA-NOT-READY"
    )

    ready["private_beta_decision"] = "PRIVATE-BETA-READY"
    with pytest.raises(verifier.ProfileViolation, match="^STATUS_DECISION_INVALID$"):
        verifier.private_beta_status_snapshot_from_bytes(_canonical(ready))


def _copy_fixture(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    for relative in (
        "src/agentguardian",
        ".github/workflows",
        "docs/security",
        "packaging/windows",
        "rules",
    ):
        shutil.copytree(ROOT / relative, root / relative)
    for relative in (
        "README.md",
        "docs/architecture.md",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "pyproject.toml",
        "requirements-build.lock",
        "requirements-dev.lock",
        "scripts/build_windows_installer.py",
        "scripts/build_windows_portable.py",
        "scripts/run_personal_privacy_acceptance.py",
        "scripts/verify_personal_release_profile.py",
        "scripts/verify_windows_installer_candidate.py",
        "scripts/verify_windows_installer_lifecycle_evidence.py",
        "release_profiles/personal_exe_private_beta.json",
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    return root


def _write_profile(root: Path, profile: dict[str, object]) -> Path:
    path = root / "release_profiles" / "personal_exe_private_beta.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(profile))
    return path


def _verify_profile(verifier, root: Path) -> dict[str, str]:
    snapshot = verifier.load_profile_snapshot(
        root, "release_profiles/personal_exe_private_beta.json"
    )
    return verifier.verify_profile(root, snapshot)


def test_repository_matches_canonical_personal_exe_private_beta_profile() -> None:
    verifier = _verifier()
    profile = _profile()

    assert "forbidden_runtime_names" in profile
    assert "forbidden_runtime_members" in profile
    assert "forbidden_runtime_member_prefixes" in profile
    assert "forbidden_runtime_references" not in profile
    assert PROFILE_PATH.read_bytes() == _canonical(profile)
    assert _verify_profile(verifier, ROOT) == {
        "profile": "personal_exe_private_beta",
        "status": "pass",
    }


def test_active_personal_docs_replace_stale_release_history() -> None:
    profile = _profile()
    expected_paths = sorted(
        [
            path.relative_to(ROOT).as_posix()
            for path in (*ACTIVE_PERSONAL_DOCS, PRIVATE_BETA_STATUS_PATH)
        ]
    )
    assert profile["active_document_paths"] == expected_paths

    documents = {
        path.name: path.read_text(encoding="utf-8") for path in ACTIVE_PERSONAL_DOCS
    }
    combined = "\n".join(documents.values())
    active_overview = documents["README.md"] + documents["architecture.md"]

    for required in (
        "personal non-regulated configuration",
        "Windows 11 x64",
        "Personal v1 permanently excludes MCP runtime integration.",
        "The runtime must not call OpenAI or another provider API by default.",
        "0.2.0-beta.1",
        "NO-GO",
    ):
        assert required in combined

    assert "Batch 3" not in active_overview
    assert "Batch 4" not in active_overview
    assert "Batch 5" not in active_overview
    assert "Batch 6" not in active_overview
    assert " passed," not in active_overview
    assert set(re.findall(r"\b[0-9a-f]{40}\b", active_overview)) == {
        FROZEN_PRIVATE_BETA_COMMIT
    }
    _assert_no_machine_specific_paths(combined)
    _assert_no_premature_release_claims(combined)


@pytest.mark.parametrize(
    "path",
    (
        r"C:\Users\Synthetic\AgentGuardian\report.json",
        r"\\server\share\AgentGuardian\report.json",
    ),
    ids=("drive-qualified", "unc"),
)
def test_active_personal_doc_path_guard_rejects_machine_specific_paths(
    path: str,
) -> None:
    with pytest.raises(AssertionError, match="machine-specific path"):
        _assert_no_machine_specific_paths(path)


def test_active_personal_release_claim_guard_rejects_premature_status() -> None:
    for claim in _PREMATURE_RELEASE_CLAIMS:
        multiline_claim = claim.replace(" ", "\n", 1)
        for rendered_claim in (claim, claim.swapcase(), multiline_claim):
            with pytest.raises(AssertionError, match="premature claim"):
                _assert_no_premature_release_claims(rendered_claim)


def test_governing_and_historical_document_classes_are_explicit() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    design = GOVERNING_PERSONAL_DOCS[0].read_text(encoding="utf-8")
    runbook = (SECURITY_DOCS / "personal-v1-release-runbook.md").read_text(
        encoding="utf-8"
    )

    for path in GOVERNING_PERSONAL_DOCS:
        assert path.relative_to(ROOT).as_posix() in readme
    assert "govern development" in readme
    assert "not product capability claims or release evidence" in readme
    assert "approved active product specification" in design
    assert "implementation has not started" not in design
    assert ACTIVE_INTEGRATIONS_PREVIEW_DOC.is_file()
    assert "INTEGRATIONS-PREVIEW-NOT-READY" in ACTIVE_INTEGRATIONS_PREVIEW_DOC.read_text(
        encoding="utf-8"
    )
    assert ACTIVE_INTEGRATIONS_PREVIEW_DOC not in HISTORICAL_SECURITY_DOCS

    excluded_security_docs = {
        path
        for path in SECURITY_DOCS.glob("*.md")
        if path not in ACTIVE_PERSONAL_DOCS
        and path != ACTIVE_INTEGRATIONS_PREVIEW_DOC
    }
    assert excluded_security_docs == set(HISTORICAL_SECURITY_DOCS)
    for path in HISTORICAL_SECURITY_DOCS:
        text = path.read_text(encoding="utf-8")
        assert "HISTORICAL AND NON-GOVERNING" in text
        assert "personal_exe_private_beta" in text
        assert "not readiness evidence" in text

    for stale_branch_inventory in (
        "default branch had CI and Windows MVP workflows only",
        "default branch contained CI and Windows MVP workflows only",
        "Store workflow was not present on the default branch",
        "2026-08-17",
    ):
        assert stale_branch_inventory not in readme
        assert stale_branch_inventory not in runbook


def test_active_architecture_domain_inventory_matches_source() -> None:
    import dataclasses

    from agentguardian import domain

    architecture = (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")
    match = re.search(
        r"<!-- domain-field-inventory -->\s*```json\s*(\{.*?\})\s*```",
        architecture,
        flags=re.DOTALL,
    )
    assert match is not None
    assert json.loads(match.group(1)) == {
        contract.__name__: [field.name for field in dataclasses.fields(contract)]
        for contract in (
            domain.Asset,
            domain.Evidence,
            domain.Finding,
            domain.Score,
            domain.RemediationPlan,
            domain.VerificationResult,
        )
    }


def test_personal_privacy_support_and_acceptance_contracts_are_explicit() -> None:
    privacy = (SECURITY_DOCS / "personal-v1-privacy.md").read_text(encoding="utf-8")
    support = (SECURITY_DOCS / "personal-v1-support.md").read_text(encoding="utf-8")
    runbook = (SECURITY_DOCS / "personal-v1-release-runbook.md").read_text(
        encoding="utf-8"
    )
    machines = (
        SECURITY_DOCS / "personal-v1-independent-machine-acceptance.md"
    ).read_text(encoding="utf-8")

    for marker in (
        "local reads",
        "temporary copy",
        "one-time in-memory read",
        "DPAPI-protected state",
        "explicit public URL",
        "user deletion",
        "no provider API call by default",
    ):
        assert marker in privacy

    assert "https://github.com/yangjing6213-dev/AgentGuardian/issues" in support
    assert "ordinary support: live" in support
    assert "GitHub Private Vulnerability Reporting is currently disabled." in support
    assert "No private vulnerability intake is currently available." in support
    assert "Do not submit sensitive vulnerability details in a public Issue." in support
    assert "operations/security channel gate: pending" in support
    assert not re.search(r"[\w.+-]+@[\w.-]+", support)

    assert "This runbook is a release gate, not a production-safety claim." in runbook
    for marker in (
        "same source commit S",
        "canonical external record",
        "repository license template remains pending",
        "must not be written back into S",
        "formal package must be built from S",
    ):
        assert marker in runbook

    for marker in (
        "two newly provisioned Windows 11 x64 machines",
        "25H2",
        "24H2 or 25H2",
        "no development tools",
        "installer SHA-256",
        "Unknown Publisher or SmartScreen",
        "installer identity and version",
        "install and launch",
        "eligible scan",
        "browser metadata",
        "clipboard",
        "share reachability",
        "remediation and rollback",
        "report comparison",
        "crash and restart",
        "upgrade",
        "uninstall and residue",
        "machine ID hash",
    ):
        assert marker in machines
    assert "private Store" not in machines
    assert "signature" not in machines
    for forbidden in ("username", "full path", "user content"):
        assert f"never record {forbidden}" in machines


def test_active_documents_report_current_candidate_without_readiness_claim() -> None:
    for path in ACTIVE_PERSONAL_DOCS:
        text = " ".join(path.read_text(encoding="utf-8").split())
        assert "no real installer EXE" not in text
        assert "successful native workflow execution evidence" not in text

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (SECURITY_DOCS / "personal-v1-release-runbook.md").read_text(
        encoding="utf-8"
    )
    for text in (readme, runbook):
        assert FROZEN_PRIVATE_BETA_COMMIT in text
        assert "PRIVATE-BETA-NOT-READY" in text
        assert "formal public release remains `NO-GO`" in text
        assert "external license and Qt" in text
        assert "two-machine" in text
        assert "operations/security" in text
    assert "canonical gate template" not in readme
    assert "canonical partial status ledger" in readme


def test_release_status_is_canonical_eight_gate_ledger() -> None:
    status = json.loads(PRIVATE_BETA_STATUS_PATH.read_text(encoding="ascii"))
    assert PRIVATE_BETA_STATUS_PATH.read_bytes() == _canonical(status)
    snapshot = _verifier().load_private_beta_status_snapshot(
        ROOT, PRIVATE_BETA_STATUS_PATH
    )
    assert _verifier().verify_private_beta_status(snapshot)["private_beta"] == (
        "PRIVATE-BETA-NOT-READY"
    )


def test_release_status_is_forced_to_lf_in_git_attributes() -> None:
    attributes = (ROOT / ".gitattributes").read_text(encoding="ascii").splitlines()
    assert "docs/security/personal-exe-private-beta-status.json text eol=lf" in attributes


def test_release_evidence_is_forced_to_lf_in_git_attributes() -> None:
    for path in (
        PRIVATE_BETA_EVIDENCE_PATH,
        PRIVATE_BETA_LOCAL_EVIDENCE_PATH,
        PRIVATE_BETA_PRIVACY_EVIDENCE_PATH,
        PRIVATE_BETA_GITLEAKS_CONFIG_PATH,
    ):
        result = subprocess.run(
            (
                "git",
                "check-attr",
                "eol",
                "--",
                path.relative_to(ROOT).as_posix(),
            ),
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

        assert result.stdout.strip().endswith(": eol: lf")


def test_frozen_candidate_secret_scan_allowlist_is_narrow() -> None:
    config = tomllib.loads(
        PRIVATE_BETA_GITLEAKS_CONFIG_PATH.read_text(encoding="ascii")
    )

    assert config == {
        "extend": {"useDefault": True},
        "allowlists": [
            {
                "condition": "AND",
                "description": "Reviewed source-policy SHA-256 entries",
                "paths": [r"^src/agentguardian/source_policy\.json$"],
                "regexTarget": "line",
                "regexes": [
                    r'^\s*"[a-z0-9_]+\.py":\s*"[0-9a-f]{64}",?\s*$'
                ],
                "targetRules": ["generic-api-key"],
            }
        ],
    }


def test_release_status_contract_accepts_evidence_bound_transitions() -> None:
    verifier = _verifier()
    ready = _passing_private_beta_status()
    snapshot = verifier.private_beta_status_snapshot_from_bytes(_canonical(ready))
    assert verifier.verify_private_beta_status(snapshot)["private_beta"] == (
        "PRIVATE-BETA-READY"
    )


def test_task_8_freezes_exe_candidate_before_gates_and_avoids_self_reference() -> None:
    plan = (
        ROOT
        / "docs"
        / "superpowers"
        / "plans"
        / "2026-08-21-agentguardian-personal-exe-private-beta.md"
    ).read_text(encoding="utf-8")
    task_8 = plan.split("### Task 8:", 1)[1]
    design = (
        ROOT
        / "docs"
        / "superpowers"
        / "specs"
        / "2026-08-21-agentguardian-personal-exe-private-beta-design.md"
    ).read_text(encoding="utf-8")
    normalized_design = " ".join(design.split())
    normalized_task_8 = " ".join(task_8.split())

    assert "Candidate SHA: exact clean commit `S`" in task_8
    assert "A later ledger-only commit may bind evidence to `S`" in normalized_design
    assert "Any change to source, dependencies, compiler, version" in design
    assert "PRIVATE-BETA-READY" in task_8
    assert "Formal public release remains `NO-GO`" in normalized_task_8
    assert "0.2.0-beta.1" in design
    for retired_term in ("Store identity", "personal_store_release", "1.0.0"):
        assert retired_term not in task_8


def test_profile_is_git_bound_to_lf_line_endings() -> None:
    result = subprocess.run(
        (
            "git",
            "check-attr",
            "eol",
            "--",
            "release_profiles/personal_exe_private_beta.json",
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip().endswith(": eol: lf")


@pytest.mark.parametrize("explicit_profile", [True, False])
def test_selecting_frozen_personal_profile_against_current_03_source_fails_before_pyinstaller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, explicit_profile: bool
) -> None:
    import scripts.build_windows_portable as build_module

    commit = "a" * 40
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(build_module.sys, "platform", "win32")
    monkeypatch.setattr(build_module.sys, "version_info", (3, 12))
    monkeypatch.setattr(
        build_module,
        "_git",
        lambda _root, *arguments: commit if arguments == ("rev-parse", "HEAD") else "",
    )
    monkeypatch.setattr(
        build_module.subprocess,
        "run",
        lambda *arguments, **kwargs: calls.append(arguments),
    )

    arguments = {
        "source_commit": commit,
        "built_at": "2026-08-25T00:00:00Z",
    }
    if explicit_profile:
        arguments["release_profile"] = "personal_exe_private_beta"
    with pytest.raises(ValueError, match="RELEASE_PROFILE_SOURCE_IDENTITY_MISMATCH"):
        build_module.build_portable(ROOT, tmp_path / "output", **arguments)
    assert calls == []


@pytest.mark.parametrize(
    "mutation,code",
    (
        (lambda value: value.update({"unknown": []}), "PROFILE_SCHEMA_INVALID"),
        (
            lambda value: value["required_source_paths"].reverse(),
            "PROFILE_ARRAY_INVALID",
        ),
    ),
)
def test_profile_rejects_unknown_or_unsorted_values(
    tmp_path: Path, mutation, code: str
) -> None:
    verifier = _verifier()
    profile = _profile()
    mutation(profile)
    path = _write_profile(tmp_path, profile)

    with pytest.raises(verifier.ProfileViolation, match=f"^{code}$"):
        verifier.load_profile_snapshot(tmp_path, path)


def test_profile_rejects_duplicate_keys_and_oversized_json(tmp_path: Path) -> None:
    verifier = _verifier()
    path = tmp_path / "profile.json"
    path.write_bytes(b'{"schema":1,"schema":1}\n')
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_JSON_INVALID$"):
        verifier.load_profile_snapshot(tmp_path, path)

    path.write_bytes(b" " * (64 * 1024 + 1))
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_JSON_TOO_LARGE$"):
        verifier.load_profile_snapshot(tmp_path, path)


def test_profile_rejects_crlf_canonical_json(tmp_path: Path) -> None:
    verifier = _verifier()
    path = tmp_path / "profile.json"
    path.write_bytes(PROFILE_PATH.read_bytes().replace(b"\n", b"\r\n"))

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_JSON_INVALID$"):
        verifier.load_profile_snapshot(tmp_path, path)


@pytest.mark.parametrize("field,value", (("schema", 1), ("name", "personal_release")))
def test_profile_requires_exact_schema_and_name(
    tmp_path: Path, field: str, value: object
) -> None:
    verifier = _verifier()
    profile = _profile()
    profile[field] = value

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_SCHEMA_INVALID$"):
        verifier.load_profile_snapshot(tmp_path, _write_profile(tmp_path, profile))


@pytest.mark.parametrize(
    "value",
    (
        "/absolute/*.py",
        "C:/absolute/*.py",
        "file:/absolute/*.py",
        "../escape.py",
        "src/../escape.py",
        "src/./bad.py",
        "src//bad.py",
        "src/bad.py/",
        "src/carrier:stream/bad.py",
        "src\\bad.py",
    ),
)
def test_profile_rejects_unsafe_globs(tmp_path: Path, value: str) -> None:
    verifier = _verifier()
    profile = _profile()
    profile["forbidden_source_globs"] = sorted(
        [*profile["forbidden_source_globs"], value]
    )
    path = _write_profile(tmp_path, profile)

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PATH_INVALID$"):
        verifier.load_profile_snapshot(tmp_path, path)


@pytest.mark.parametrize(
    "value",
    ("", ".", "..", "../profile.json", "release_profiles/../profile.json", "release_profiles\\profile.json"),
)
def test_profile_snapshot_rejects_unsafe_relative_actual_paths(
    tmp_path: Path, value: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PATH_INVALID$") as caught:
        verifier.load_profile_snapshot(root, value)

    assert str(caught.value) == "PROFILE_PATH_INVALID"
    assert str(root) not in str(caught.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows native Path regression")
def test_profile_snapshot_accepts_native_relative_path_object(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)

    snapshot = verifier.load_profile_snapshot(
        root, Path("release_profiles") / "personal_exe_private_beta.json"
    )

    assert snapshot.profile["name"] == "personal_exe_private_beta"


@pytest.mark.skipif(os.name != "nt", reason="Windows native Path regression")
@pytest.mark.parametrize(
    "value",
    (
        Path(),
        Path("..") / "profile.json",
        Path("release_profiles") / "carrier:profile",
        Path("C:profile.json"),
    ),
)
def test_profile_snapshot_rejects_unsafe_native_relative_path_objects(
    tmp_path: Path, value: Path
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PATH_INVALID$"):
        verifier.load_profile_snapshot(root, value)


def test_profile_path_rejects_windows_rooted_relative_before_filesystem_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _verifier()

    class SimulatedWindowsPath(PureWindowsPath):
        def absolute(self):
            return self

    probes: list[PureWindowsPath] = []

    def reject_probe(path: PureWindowsPath) -> bool:
        probes.append(path)
        pytest.fail("rooted-relative profile path reached filesystem inspection")

    monkeypatch.setattr(verifier, "Path", SimulatedWindowsPath)
    monkeypatch.setattr(verifier, "_has_reparse_component", reject_probe)

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PATH_INVALID$") as caught:
        verifier._resolved_profile_path(
            SimulatedWindowsPath("C:/project"),
            SimulatedWindowsPath(r"\Windows\win.ini"),
        )

    assert str(caught.value) == "PROFILE_PATH_INVALID"
    assert probes == []


def test_profile_snapshot_rejects_symlink_escape_before_resolution(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    shutil.copyfile(PROFILE_PATH, outside / "profile.json")
    link = root / "release_profiles" / "linked"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_REPARSE_POINT$") as caught:
        verifier.load_profile_snapshot(root, "release_profiles/linked/profile.json")

    assert str(caught.value) == "PROFILE_REPARSE_POINT"
    assert str(outside) not in str(caught.value)


def test_profile_snapshot_rejects_reparse_escape_deterministically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    linked = root / "release_profiles" / "linked"
    linked.mkdir()
    shutil.copyfile(PROFILE_PATH, linked / "profile.json")
    original = verifier._is_reparse_point
    monkeypatch.setattr(
        verifier,
        "_is_reparse_point",
        lambda path: path == linked or original(path),
    )

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_REPARSE_POINT$") as caught:
        verifier.load_profile_snapshot(root, "release_profiles/linked/profile.json")

    assert str(caught.value) == "PROFILE_REPARSE_POINT"
    assert str(linked) not in str(caught.value)


@pytest.mark.parametrize("absolute", (False, True))
def test_profile_snapshot_rejects_ntfs_ads_path_when_supported(
    tmp_path: Path, absolute: bool
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    carrier = root / "release_profiles" / "carrier"
    carrier.write_bytes(b"carrier")
    ads = Path(str(carrier) + ":profile")
    try:
        ads.write_bytes(PROFILE_PATH.read_bytes())
    except OSError:
        pytest.skip("NTFS alternate data streams are unavailable")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PATH_INVALID$") as caught:
        verifier.load_profile_snapshot(
            root, ads if absolute else "release_profiles/carrier:profile"
        )

    assert str(caught.value) == "PROFILE_PATH_INVALID"
    assert str(carrier) not in str(caught.value)


def test_profile_rejects_case_colliding_globs(tmp_path: Path) -> None:
    verifier = _verifier()
    profile = _profile()
    original = profile["forbidden_source_globs"][0]
    profile["forbidden_source_globs"] = sorted(
        [*profile["forbidden_source_globs"], original.upper()]
    )

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_ARRAY_INVALID$"):
        verifier.load_profile_snapshot(tmp_path, _write_profile(tmp_path, profile))


@pytest.mark.parametrize(
    "relative",
    (
        "requirements-enterprise.lock",
        "src/agentguardian/enterprise_policy.py",
        "src/agentguardian/sensitive_mode.py",
        "src/agentguardian/mcp_sandbox.py",
        "src/agentguardian/windows_appcontainer.py",
        "src/agentguardian/windows_code_signing.py",
        "src/agentguardian/windows_job_object.py",
        "scripts/download_trusted_mcp_adapter.py",
        "scripts/run_windows_mcp_adapter_acceptance.py",
        ".github/workflows/windows-mvp-signed.yml",
    ),
)
def test_profile_rejects_each_forbidden_source_class_case_insensitively(
    tmp_path: Path, relative: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    path = root / relative.upper()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("forbidden", encoding="utf-8")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_SOURCE_FORBIDDEN$"):
        _verify_profile(verifier, root)


def test_double_star_forbidden_source_glob_matches_nested_path(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    profile = _profile()
    profile["forbidden_source_globs"] = sorted(
        [*profile["forbidden_source_globs"], "**/blocked.py"]
    )
    _write_profile(root, profile)
    blocked = root / "unlisted" / "nested" / "blocked.py"
    blocked.parent.mkdir(parents=True)
    blocked.write_text("blocked", encoding="utf-8")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_SOURCE_FORBIDDEN$"):
        snapshot = verifier.load_profile_snapshot(
            root, "release_profiles/personal_exe_private_beta.json"
        )
        verifier.verify_profile(root, snapshot)


@pytest.mark.parametrize("noise", ("build", "dist", "__pycache__"))
def test_double_star_glob_scans_nested_operational_noise_names(
    tmp_path: Path, noise: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    profile = _profile()
    profile["forbidden_source_globs"] = sorted(
        [*profile["forbidden_source_globs"], "**/blocked.py"]
    )
    _write_profile(root, profile)
    blocked = root / "nested" / noise / "blocked.py"
    blocked.parent.mkdir(parents=True)
    blocked.write_text("blocked", encoding="utf-8")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_SOURCE_FORBIDDEN$"):
        _verify_profile(verifier, root)


def test_root_operational_noise_remains_excluded(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    profile = _profile()
    profile["forbidden_source_globs"] = sorted(
        [*profile["forbidden_source_globs"], "**/blocked.py"]
    )
    _write_profile(root, profile)
    for noise in ("build", "dist", "__pycache__", ".pytest_cache"):
        blocked = root / noise / "blocked.py"
        blocked.parent.mkdir(parents=True)
        blocked.write_text("root noise", encoding="utf-8")

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_project_traversal_rejects_case_colliding_entries_when_supported(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    directory = root / "collision"
    directory.mkdir()
    upper = directory / "Entry.txt"
    lower = directory / "entry.txt"
    upper.write_text("upper", encoding="utf-8")
    lower.write_text("lower", encoding="utf-8")
    if len(tuple(directory.iterdir())) != 2:
        pytest.skip("case-distinct filenames are unavailable")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PROJECT_INVALID$"):
        _verify_profile(verifier, root)


@pytest.mark.parametrize(
    "relative",
    (
        "adapters/tool.exe",
        "_internal/ADAPTERS/tool.exe",
        "_internal/McpAdapter-x64.exe",
        "_internal/agentguardian/ENTERPRISE_POLICY.PYC",
        "_internal/agentguardian/sensitive_mode.py",
        "scripts/RUN_WINDOWS_MCP_ADAPTER_ACCEPTANCE.PY",
    ),
)
def test_payload_rejects_retired_names_under_any_prefix(
    tmp_path: Path, relative: str
) -> None:
    verifier = _verifier()
    bundle = tmp_path / "bundle"
    path = bundle / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"synthetic")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PAYLOAD_FORBIDDEN$"):
        verifier.verify_payload(bundle, verifier.load_profile_snapshot(ROOT, PROFILE_PATH))


def test_payload_rejects_enumerated_colon_component(tmp_path: Path) -> None:
    verifier = _verifier()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    colon_entry = bundle / "nested" / "carrier:stream"
    colon_entry.parent.mkdir()
    colon_entry.write_bytes(b"synthetic")
    if not any(path.name == "carrier:stream" for path in colon_entry.parent.iterdir()):
        pytest.skip("colon entry is not enumerable on this filesystem")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_PAYLOAD_INVALID$") as caught:
        verifier.verify_payload(
            bundle, verifier.load_profile_snapshot(ROOT, PROFILE_PATH)
        )

    assert str(caught.value) == "PROFILE_PAYLOAD_INVALID"
    assert str(bundle) not in str(caught.value)


def test_payload_rejects_symlink_or_reparse_entry_when_supported(tmp_path: Path) -> None:
    verifier = _verifier()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    target = tmp_path / "target"
    target.write_bytes(b"target")
    try:
        os.symlink(target, bundle / "linked")
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_REPARSE_POINT$"):
        verifier.verify_payload(bundle, verifier.load_profile_snapshot(ROOT, PROFILE_PATH))


def test_payload_rejects_reparse_entry_deterministically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _verifier()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    residue = bundle / "residue"
    residue.write_bytes(b"synthetic")
    original = verifier._is_reparse_point
    monkeypatch.setattr(
        verifier,
        "_is_reparse_point",
        lambda path: path == residue or original(path),
    )

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_REPARSE_POINT$"):
        verifier.verify_payload(bundle, verifier.load_profile_snapshot(ROOT, PROFILE_PATH))


@pytest.mark.parametrize(
    "source,code",
    (
        ("import subprocess\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("from importlib import import_module\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("import openai\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("import anthropic\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("import sentry_sdk\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("import builtins as b\nrunner = b.compile\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("from builtins import eval as runner\n", "PROFILE_RUNTIME_IMPORT_FORBIDDEN"),
        ("from os import system as runner\n", "PROFILE_RUNTIME_REFERENCE_FORBIDDEN"),
        (
            "from PySide6.QtCore import QProcess as process\n",
            "PROFILE_RUNTIME_REFERENCE_FORBIDDEN",
        ),
        ("exec('pass')\n", "PROFILE_RUNTIME_REFERENCE_FORBIDDEN"),
        (
            "import os\nos.system('command')\n",
            "PROFILE_RUNTIME_REFERENCE_FORBIDDEN",
        ),
        (
            "from .mcp_sandbox import run_mcp_sandbox\n",
            "PROFILE_RUNTIME_SYMBOL_FORBIDDEN",
        ),
        ("SensitiveModePolicy()\n", "PROFILE_RUNTIME_SYMBOL_FORBIDDEN"),
        ("def _enterprise_page():\n    pass\n", "PROFILE_RUNTIME_SYMBOL_FORBIDDEN"),
    ),
)
def test_runtime_ast_rejects_removed_dynamic_llm_telemetry_and_process_code(
    tmp_path: Path, source: str, code: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(verifier.ProfileViolation, match=f"^{code}$"):
        _verify_profile(verifier, root)


@pytest.mark.parametrize(
    "source",
    (
        "from os import *\nsystem('command')\n",
        "from os import *\nexecv('tool', ('tool',))\n",
        "from multiprocessing import *\nProcess()\n",
        "from asyncio import *\ncreate_subprocess_exec('tool')\n",
        "from benign_module import *\nvalue = harmless\n",
    ),
)
def test_runtime_ast_rejects_all_wildcard_imports_before_name_analysis(
    tmp_path: Path, source: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_WILDCARD_IMPORT_FORBIDDEN$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_WILDCARD_IMPORT_FORBIDDEN"
    assert str(root) not in str(caught.value)
    assert source.strip() not in str(caught.value)


def test_runtime_ast_allows_explicit_allowed_imports(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/allowed_imports.py").write_text(
        "from pathlib import Path\n"
        "from sqlite3 import connect\n"
        "path = Path('.')\n"
        "connection = connect(':memory:')\n",
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root) == {
        "profile": "personal_exe_private_beta",
        "status": "pass",
    }


@pytest.mark.parametrize(
    "source",
    (
        "import PySide6.QtCore\nPySide6.QtCore.QProcess.startDetached('tool')\n",
        "import PySide6.QtCore as qc\nqc.QProcess.start('tool')\n",
        "import PySide6.QtCore as qc\nmodule = qc\nproc = module.QProcess\n",
        "from PySide6.QtCore import QProcess\nrunner = QProcess.startDetached\nrunner('tool')\n",
        "import PySide6.QtCore\nproc = PySide6.QtCore.QProcess\nproc.start('tool')\n",
        "import PySide6.QtCore as qc\nfirst = qc.QProcess\nsecond = first\nsecond.start('tool')\n",
        "import PySide6.QtCore as qc\nfirst = qc.QProcess\nsecond = first\nfirst = second\nsecond.start('tool')\n",
        "import os\nmodule = os\nrunner = module.system\n",
        "import multiprocessing\nrunner = multiprocessing.Process\n",
        "runner = getattr(module, 'system')\n",
        "runner = getattr(module, 'QProcess')\n",
        "runner = getattr(module, 'popen')\n",
        "runner = getattr(module, 'execv')\n",
        "runner = eval\n",
    ),
)
def test_runtime_ast_rejects_qualified_and_aliased_forbidden_references(
    tmp_path: Path, source: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_REFERENCE_FORBIDDEN$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_REFERENCE_FORBIDDEN"
    assert str(root) not in str(caught.value)
    assert source.strip() not in str(caught.value)


def test_runtime_ast_rejects_subprocess_import_before_reference_scan(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    source = "import subprocess\nrunner = subprocess.run\nrunner(('tool',))\n"
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_IMPORT_FORBIDDEN$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_IMPORT_FORBIDDEN"


def test_runtime_ast_preserves_benign_aliases_and_noncalled_literals(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/benign_alias.py").write_text(
        "import sqlite3 as database\n"
        "connect = database.connect\n"
        "open_database = connect\n"
        "open_database(':memory:')\n"
        "left = right\nright = left\n"
        "import os\npath_value = os.fspath('.')\n"
        "safe_one = getattr(object(), 'st_file_attributes', 0)\n"
        "safe_two = getattr(object(), 'FILE_ATTRIBUTE_REPARSE_POINT', 0)\n"
        "class Library:\n"
        "    def compile(self): return None\n"
        "    def eval(self): return None\n"
        "    def exec(self): return None\n"
        "    def start(self): return None\n"
        "library = Library()\n"
        "library.compile(); library.eval(); library.exec(); library.start()\n"
        "DETECTOR_NAMES = ('subprocess.run', 'builtins.exec', 'QProcess.start')\n",
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_runtime_ast_allows_benign_same_names_without_forbidden_rhs(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/benign_alias.py").write_text(
        "def first():\n"
        "    runner = len\n"
        "    return runner(())\n"
        "def benign_call():\n"
        "    runner = print\n"
        "    runner('ok')\n",
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_runtime_ast_rejects_forbidden_reference_without_call(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(
        "import PySide6.QtCore as qc\n"
        "def forbidden_reference():\n"
        "    runner = qc.QProcess.start\n"
        "    return runner\n",
        encoding="utf-8",
    )

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_REFERENCE_FORBIDDEN$"
    ):
        _verify_profile(verifier, root)


def test_runtime_ast_rejects_reference_even_when_later_shadowed(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    source = root / "src/agentguardian/alias_order.py"
    source.write_text(
        "import PySide6.QtCore as qc\n"
        "runner = qc.QProcess.start\n"
        "runner = print\n"
        "runner('ok')\n",
        encoding="utf-8",
    )
    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_REFERENCE_FORBIDDEN$"
    ):
        _verify_profile(verifier, root)

    source.write_text(
        "runner = print\n"
        "runner = len\n"
        "runner(())\n",
        encoding="utf-8",
    )
    assert _verify_profile(verifier, root)["status"] == "pass"


def test_runtime_ast_allows_nested_benign_names_and_parameter_shadowing(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/benign_nested.py").write_text(
        "runner = print\n"
        "def outer():\n"
        "    runner = len\n"
        "    def inner(runner):\n"
        "        runner('ok')\n"
        "    inner(print)\n"
        "    safe_lambda = lambda runner: runner('ok')\n"
        "    safe_lambda(print)\n"
        "outer()\n",
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_runtime_ast_scans_forbidden_reference_in_branch(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(
        "import PySide6.QtCore as qc\n"
        "runner = print\n"
        "if condition:\n"
        "    runner = qc.QProcess.start\n"
        "else:\n"
        "    runner = print\n"
        "runner('tool')\n",
        encoding="utf-8",
    )

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_REFERENCE_FORBIDDEN$"
    ):
        _verify_profile(verifier, root)


@pytest.mark.parametrize(
    "source",
    (
        "import os\nfor callback in (os.system,):\n    pass\n",
        "import os\ncallbacks = [os.system for _ in range(1)]\n",
        "import os\ndef run(callback=os.system):\n    return callback\n",
        "import os\nregister(os.system)\n",
        "from functools import partial\nimport os\ncallback = partial(os.system, 'tool')\n",
        "import os\ntry:\n    callback = os.system\nexcept Exception:\n    pass\n",
        "import os\nif (callback := os.system):\n    pass\n",
        "import os\ndef callback():\n    return os.system\n",
    ),
)
def test_runtime_ast_rejects_forbidden_reference_in_every_expression_context(
    tmp_path: Path, source: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_REFERENCE_FORBIDDEN$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_REFERENCE_FORBIDDEN"
    assert str(root) not in str(caught.value)
    assert source.strip() not in str(caught.value)


@pytest.mark.parametrize("statement", ("pass\n", "0\n"))
def test_runtime_ast_node_limit_fails_closed_quickly_with_fixed_code(
    tmp_path: Path, statement: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    source = statement * 20_000
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    started = time.monotonic()
    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_ANALYSIS_LIMIT$"
    ) as caught:
        _verify_profile(verifier, root)
    elapsed = time.monotonic() - started

    assert str(caught.value) == "PROFILE_RUNTIME_ANALYSIS_LIMIT"
    assert str(root) not in str(caught.value)
    assert source.strip() not in str(caught.value)
    assert elapsed < 10.0


def test_runtime_source_byte_limit_fails_with_fixed_code(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    source = root / "src/agentguardian/hostile.py"
    source.write_bytes(b"#" * (256 * 1024 + 1))

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_ANALYSIS_LIMIT$"
    ):
        _verify_profile(verifier, root)


def test_runtime_parser_resource_failure_is_bounded_and_redacted(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    source = "value = " + "+".join("1" for _ in range(12_000)) + "\n"
    assert len(source.encode("utf-8")) < verifier.MAX_RUNTIME_SOURCE_BYTES
    (root / "src/agentguardian/hostile.py").write_text(source, encoding="utf-8")

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_ANALYSIS_LIMIT$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_ANALYSIS_LIMIT"
    assert str(root) not in str(caught.value)


@pytest.mark.parametrize(
    "failure", (RecursionError, MemoryError, OverflowError, SystemError)
)
def test_runtime_parser_resource_exceptions_use_fixed_limit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: type[BaseException],
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)

    def fail_parse(_source: bytes):
        raise failure()

    monkeypatch.setattr(verifier, "ast", SimpleNamespace(parse=fail_parse))
    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_RUNTIME_ANALYSIS_LIMIT$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_RUNTIME_ANALYSIS_LIMIT"
    assert str(root) not in str(caught.value)


def test_network_import_set_rejects_undeclared_and_missing_modules(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/hostile.py").write_text(
        "from requests import get\n", encoding="utf-8"
    )
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_NETWORK_SET_INVALID$"):
        _verify_profile(verifier, root)

    (root / "src/agentguardian/hostile.py").unlink()
    (root / "src/agentguardian/share_verification.py").write_text(
        "def verify_public_share():\n    return None\n", encoding="utf-8"
    )
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_NETWORK_SET_INVALID$"):
        _verify_profile(verifier, root)


def test_self_audit_detector_literals_do_not_false_positive(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/self_audit.py").write_text(
        'DETECTOR_LITERALS = ("subprocess", "exec", "McpSandboxPolicy", "openai")\n',
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_runtime_ast_retains_ctypes_sqlite_and_file_write_capabilities(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/retained.py").write_text(
        "import ctypes\nimport sqlite3\nfrom pathlib import Path\n"
        "sqlite3.connect(':memory:')\nPath('local').write_text('value')\n"
        "ctypes.c_void_p()\n",
        encoding="utf-8",
    )

    (root / "src/agentguardian/rebound_aliases.py").write_text(
        "def ctypes_value():\n"
        "    import ctypes as library\n"
        "    return library.c_void_p()\n"
        "def sqlite_value():\n"
        "    import sqlite3 as library\n"
        "    return library.connect(':memory:')\n",
        encoding="utf-8",
    )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_workflow_allows_normal_build_commands_but_rejects_retired_contracts(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    workflow = root / ".github/workflows/ordinary.yml"
    workflow.write_text(
        "on: workflow_dispatch\njobs:\n  build:\n    steps:\n      - run: python scripts/build_windows_portable.py\n",
        encoding="utf-8",
    )
    assert _verify_profile(verifier, root)["status"] == "pass"

    workflow.write_text("env:\n  AGENTGUARDIAN_SIGNING_PFX: retired\n", encoding="utf-8")
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_WORKFLOW_FORBIDDEN$"):
        _verify_profile(verifier, root)


def test_workflow_scans_yaml_suffix_case_insensitively(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    workflow = root / ".github/workflows/ordinary.YaMl"
    workflow.write_text(
        "on: workflow_dispatch\njobs:\n  build:\n    steps:\n"
        "      - run: python scripts/build_windows_portable.py\n",
        encoding="utf-8",
    )
    assert _verify_profile(verifier, root)["status"] == "pass"

    workflow.write_text(
        "env:\n  AGENTGUARDIAN_SIGNING_PFX: retired\n", encoding="utf-8"
    )
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_WORKFLOW_FORBIDDEN$"):
        _verify_profile(verifier, root)


def test_workflow_read_limit_fails_closed_without_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    workflow = root / ".github/workflows/oversized.yaml"
    workflow.write_text("#" * 64, encoding="utf-8")
    monkeypatch.setattr(verifier, "_MAX_WORKFLOW_FILE_BYTES", 32)

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_WORKFLOW_INVALID$") as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_WORKFLOW_INVALID"
    assert str(workflow) not in str(caught.value)


@pytest.mark.parametrize(
    "constant,code",
    (
        ("_MAX_DOCUMENT_FILE_BYTES", "PROFILE_DOCUMENT_INVALID"),
        ("_MAX_DOCUMENT_AGGREGATE_BYTES", "PROFILE_DOCUMENT_INVALID"),
    ),
)
def test_document_read_limits_fail_closed_without_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    code: str,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    monkeypatch.setattr(verifier, constant, 32)

    with pytest.raises(verifier.ProfileViolation, match=f"^{code}$") as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == code
    assert str(root) not in str(caught.value)


@pytest.mark.parametrize(
    "constant,value",
    (("_MAX_TRAVERSAL_ENTRIES", 2), ("_MAX_TRAVERSAL_DEPTH", 1)),
)
def test_project_traversal_limits_fail_closed_without_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    deep = root / "unlisted/a/b/c/value.txt"
    deep.parent.mkdir(parents=True)
    deep.write_text("value", encoding="utf-8")
    monkeypatch.setattr(verifier, constant, value)

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_PROJECT_TRAVERSAL_LIMIT$"
    ) as caught:
        _verify_profile(verifier, root)

    assert str(caught.value) == "PROFILE_PROJECT_TRAVERSAL_LIMIT"
    assert str(deep) not in str(caught.value)


def test_payload_traversal_limit_fails_closed_without_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = _verifier()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "one").write_text("one", encoding="utf-8")
    (bundle / "two").write_text("two", encoding="utf-8")
    monkeypatch.setattr(verifier, "_MAX_TRAVERSAL_ENTRIES", 1)

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_PAYLOAD_TRAVERSAL_LIMIT$"
    ) as caught:
        verifier.verify_payload(
            bundle, verifier.load_profile_snapshot(ROOT, PROFILE_PATH)
        )

    assert str(caught.value) == "PROFILE_PAYLOAD_TRAVERSAL_LIMIT"
    assert str(bundle) not in str(caught.value)


def test_static_detector_source_remains_required(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    (root / "src/agentguardian/detectors.py").unlink()

    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_REQUIRED_SOURCE_MISSING$"):
        _verify_profile(verifier, root)


def test_active_docs_reject_positive_promises_but_allow_negative_boundaries(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    readme = root / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8")
        + "\nHigh-sensitivity mode is not supported.\n",
        encoding="utf-8",
    )
    assert _verify_profile(verifier, root)["status"] == "pass"

    readme.write_text(
        readme.read_text(encoding="utf-8")
        + "\nenterprise control plane is implemented\n",
        encoding="utf-8",
    )
    with pytest.raises(verifier.ProfileViolation, match="^PROFILE_DOCUMENT_FORBIDDEN$"):
        _verify_profile(verifier, root)


@pytest.mark.parametrize(
    "stale_claim",
    (
        "Offline enterprise policy enforcement is implemented",
        "The desktop now exposes a local-only control-plane page",
        "A network-neutral enterprise service boundary now enforces",
        "A local transactional enterprise control-plane core is now implemented",
        "High-sensitivity mode disables the share-verification UI",
    ),
)
def test_active_readme_rejects_each_retired_implementation_claim(
    tmp_path: Path, stale_claim: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    readme = root / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8") + "\n" + stale_claim + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_DOCUMENT_FORBIDDEN$"
    ):
        _verify_profile(verifier, root)


@pytest.mark.parametrize(
    "relative,stale_claim",
    (
        (
            "docs/architecture.md",
            "`enterprise_policy.py` provides offline policy admission",
        ),
        (
            "docs/architecture.md",
            "`enterprise_policy.py` 提供离线策略准入",
        ),
        (
            "docs/security/personal-v1-threat-model.md",
            "`enterprise_policy.py` rejects duplicate/unknown fields",
        ),
        (
            "docs/security/personal-v1-threat-model.md",
            "Optional `enterprise_signing.py` verifies an Ed25519 envelope",
        ),
    ),
)
def test_active_architecture_and_threat_model_reject_retired_controls(
    tmp_path: Path, relative: str, stale_claim: str
) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    document = root / relative
    document.write_text(
        document.read_text(encoding="utf-8") + "\n" + stale_claim + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        verifier.ProfileViolation, match="^PROFILE_DOCUMENT_FORBIDDEN$"
    ):
        _verify_profile(verifier, root)


def test_historical_report_and_superpowers_docs_are_excluded(tmp_path: Path) -> None:
    verifier = _verifier()
    root = _copy_fixture(tmp_path)
    for relative in ("docs/reports/history.md", "docs/superpowers/history.md"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "Offline enterprise policy enforcement is implemented\n",
            encoding="utf-8",
        )

    assert _verify_profile(verifier, root)["status"] == "pass"


def test_cli_emits_bounded_canonical_json_without_private_paths(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "verify_personal_release_profile.py"
    passed = subprocess.run(
        [sys.executable, str(script), "--project-root", str(ROOT), "--profile", str(PROFILE_PATH)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert passed.returncode == 0, passed.stderr
    assert passed.stdout == '{"profile":"personal_exe_private_beta","status":"pass"}\n'
    assert passed.stderr == ""

    relative = subprocess.run(
        [
            sys.executable,
            str(script),
            "--project-root",
            str(ROOT),
            "--profile",
            "release_profiles/personal_exe_private_beta.json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert relative.returncode == 0, relative.stderr
    assert relative.stdout == '{"profile":"personal_exe_private_beta","status":"pass"}\n'
    assert relative.stderr == ""

    root = _copy_fixture(tmp_path)
    forbidden = root / "src/agentguardian/mcp_sandbox.py"
    forbidden.write_text("forbidden", encoding="utf-8")
    failed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--project-root",
            str(root),
            "--profile",
            str(root / "release_profiles/personal_exe_private_beta.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    combined = failed.stdout + failed.stderr
    assert failed.returncode != 0
    assert "PROFILE_SOURCE_FORBIDDEN" in combined
    assert str(root) not in combined
