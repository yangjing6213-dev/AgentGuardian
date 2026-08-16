import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "run_personal_privacy_acceptance.py"
RAW_MARKER = "".join(("sk", "-", "proj", "-", "PERSONAL_PRIVACY_CANARY"))
TOP_LEVEL_FIELDS = (
    "schema",
    "profile",
    "passed",
    "claims",
    "report",
    "sample",
    "clipboard",
    "browser",
    "network_observation",
    "workspace_cleanup",
)
CLAIM_FIELDS = (
    "redacted_reports",
    "clipboard_raw_retained",
    "browser_snapshot_cleaned",
    "temporary_workspace_cleaned",
    "raw_markers_absent",
    "default_api_call",
)


def _load_acceptance_module():
    assert SCRIPT_PATH.is_file(), "personal privacy acceptance script is missing"
    spec = importlib.util.spec_from_file_location(
        "run_personal_privacy_acceptance", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_personal_privacy_acceptance_writes_exact_redacted_evidence(
    tmp_path: Path,
) -> None:
    module = _load_acceptance_module()
    evidence_path = tmp_path / "personal-privacy-acceptance.json"

    result = module.run_acceptance(evidence_path)

    assert tuple(result) == TOP_LEVEL_FIELDS
    assert result["schema"] == 1
    assert result["profile"] == "personal_privacy_acceptance"
    assert result["passed"] is True
    assert tuple(result["claims"]) == CLAIM_FIELDS
    assert result["claims"] == {
        "redacted_reports": True,
        "clipboard_raw_retained": False,
        "browser_snapshot_cleaned": True,
        "temporary_workspace_cleaned": True,
        "raw_markers_absent": True,
        "default_api_call": False,
    }
    assert result["report"] == {
        "json_redacted": True,
        "html_redacted": True,
        "export_redacted": True,
        "sample_path_absent_from_json": True,
        "sample_path_absent_from_html": True,
        "sample_path_absent_from_export": True,
        "workspace_path_absent_from_json": True,
        "workspace_path_absent_from_html": True,
        "workspace_path_absent_from_export": True,
        "raw_marker_absent_from_evidence": True,
        "sample_path_absent_from_evidence": True,
        "workspace_path_absent_from_evidence": True,
    }
    assert tuple(result["sample"]) == (
        "source_kind",
        "finding_count",
        "coverage",
        "incomplete",
    )
    assert result["clipboard"] == {
        "scanned": True,
        "raw_data_retained": False,
        "raw_marker_in_findings": False,
    }
    assert result["browser"] == {
        "temporary_copy_removed": True,
        "raw_data_retained": False,
    }
    assert result["network_observation"] == {
        "scope": [
            "python_stdlib_socket_dns",
            "python_stdlib_socket_tcp_udp",
            "python_subprocess_launch",
        ],
        "native_extension_or_os_traffic": "not_observed",
        "attempt_categories": [],
    }
    assert result["workspace_cleanup"] is True
    evidence = evidence_path.read_text(encoding="utf-8")
    assert json.loads(evidence) == result
    assert RAW_MARKER not in evidence
    assert str(tmp_path) not in evidence
    assert Path.home().name.lower() not in evidence.lower()


def test_personal_privacy_acceptance_uses_supplied_sanitized_sample(
    tmp_path: Path,
) -> None:
    module = _load_acceptance_module()
    sample_root = (tmp_path / "sanitized-sample").resolve()
    sample_root.mkdir()
    (sample_root / "config.env").write_text(
        f"OPENAI_API_KEY={RAW_MARKER}\n",
        encoding="utf-8",
    )
    evidence_path = tmp_path / "supplied-sample-acceptance.json"

    result = module.run_acceptance(evidence_path, sample_root=sample_root)

    assert result["passed"] is True
    assert result["sample"]["source_kind"] == "supplied_sanitized_sample"
    assert result["sample"]["finding_count"] >= 1
    assert all(result["report"].values())
    evidence = evidence_path.read_text(encoding="utf-8")
    assert RAW_MARKER not in evidence
    assert str(sample_root) not in evidence
    assert str(tmp_path) not in evidence


@pytest.mark.parametrize("sample_kind", ("relative", "missing", "file"))
def test_personal_privacy_acceptance_rejects_hostile_sample_roots(
    tmp_path: Path, sample_kind: str
) -> None:
    module = _load_acceptance_module()
    evidence_path = tmp_path / "rejected.json"
    if sample_kind == "relative":
        sample_root = Path("relative-sample")
    elif sample_kind == "missing":
        sample_root = (tmp_path / "missing").resolve()
    else:
        sample_root = (tmp_path / "sample.txt").resolve()
        sample_root.write_text("sanitized", encoding="utf-8")

    with pytest.raises(
        ValueError, match="^sample root must be an absolute local directory$"
    ):
        module.run_acceptance(evidence_path, sample_root=sample_root)

    assert not evidence_path.exists()


def test_personal_privacy_acceptance_rejects_reparse_sample_root(
    tmp_path: Path,
) -> None:
    module = _load_acceptance_module()
    target = (tmp_path / "target").resolve()
    target.mkdir()
    link = (tmp_path / "linked-sample").resolve()
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink unavailable: {error.__class__.__name__}")

    with pytest.raises(
        ValueError, match="^sample root must be an absolute local directory$"
    ):
        module.run_acceptance(tmp_path / "rejected.json", sample_root=link)


def test_personal_privacy_claims_are_computed_from_observed_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_acceptance_module()
    evidence_path = tmp_path / "failed-acceptance.json"
    monkeypatch.setattr(
        module,
        "audit_clipboard_once",
        lambda *args, **kwargs: SimpleNamespace(
            scanned=True,
            raw_data_retained=True,
            findings=(),
        ),
    )

    with pytest.raises(RuntimeError, match="^PERSONAL_PRIVACY_ACCEPTANCE_FAILED$"):
        module.run_acceptance(evidence_path)

    result = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert result["passed"] is False
    assert result["clipboard"]["raw_data_retained"] is True
    assert result["claims"]["clipboard_raw_retained"] is True


@pytest.mark.parametrize(
    ("attempt_kind", "expected_category"),
    (
        ("dns", "dns"),
        ("tcp", "tcp"),
        ("udp", "udp"),
        ("subprocess", "subprocess"),
    ),
)
def test_real_blocker_records_safe_failure_and_restores_patches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attempt_kind: str,
    expected_category: str,
) -> None:
    module = _load_acceptance_module()
    evidence_root = tmp_path / "网络观察"
    evidence_root.mkdir()
    evidence_path = evidence_root / f"{attempt_kind}.json"
    observed_workspace_paths = []
    targets = [
        (module.socket, "getaddrinfo"),
        (module.socket, "create_connection"),
        (module.socket.socket, "connect"),
        (module.socket.socket, "connect_ex"),
        (module.socket.socket, "sendto"),
        (module.subprocess, "Popen"),
    ]
    if hasattr(module.socket.socket, "sendmsg"):
        targets.append((module.socket.socket, "sendmsg"))
    originals = [(owner, name, getattr(owner, name)) for owner, name in targets]

    def attempting_audit(roots, **kwargs):
        observed_workspace_paths.append(str(Path(roots[0]).parent))
        if attempt_kind == "dns":
            module.socket.getaddrinfo("private-target.invalid", 443)
        elif attempt_kind == "tcp":
            module.socket.create_connection(("private-target.invalid", 443))
        elif attempt_kind == "udp":
            with module.socket.socket(
                module.socket.AF_INET, module.socket.SOCK_DGRAM
            ) as client:
                client.sendto(b"private-payload", ("127.0.0.1", 9))
        else:
            module.subprocess.Popen(["private-command"])

    monkeypatch.setattr(module, "_run_audit", attempting_audit)

    with pytest.raises(RuntimeError, match="^PERSONAL_PRIVACY_ACCEPTANCE_FAILED$"):
        module.run_acceptance(evidence_path)

    evidence = evidence_path.read_text(encoding="utf-8")
    result = json.loads(evidence)
    assert result["passed"] is False
    assert result["claims"]["default_api_call"] is True
    assert result["network_observation"]["attempt_categories"] == [
        expected_category
    ]
    assert result["network_observation"]["native_extension_or_os_traffic"] == (
        "not_observed"
    )
    assert result["workspace_cleanup"] is True
    assert len(observed_workspace_paths) == 1
    for forbidden in (
        "private-target.invalid",
        "private-payload",
        "private-command",
        observed_workspace_paths[0],
        RAW_MARKER,
    ):
        assert forbidden not in evidence
    for owner, name, original in originals:
        assert getattr(owner, name) is original


def test_workspace_only_report_leak_fails_without_leaking_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_acceptance_module()
    evidence_path = tmp_path / "workspace-leak.json"
    observed_workspace_paths = []

    def leaking_audit(roots, **kwargs):
        workspace_path = str(Path(roots[0]).parent)
        observed_workspace_paths.append(workspace_path)
        return SimpleNamespace(
            report_json=json.dumps({"path": workspace_path}),
            report_html=f"<p>{workspace_path}</p>",
            findings=(object(),),
            score=SimpleNamespace(coverage=1.0, incomplete=False),
        )

    monkeypatch.setattr(module, "_run_audit", leaking_audit)

    with pytest.raises(RuntimeError, match="^PERSONAL_PRIVACY_ACCEPTANCE_FAILED$"):
        module.run_acceptance(evidence_path)

    assert len(observed_workspace_paths) == 1
    evidence = evidence_path.read_text(encoding="utf-8")
    result = json.loads(evidence)
    assert result["passed"] is False
    assert result["report"]["workspace_path_absent_from_json"] is False
    assert result["report"]["workspace_path_absent_from_html"] is False
    assert result["report"]["workspace_path_absent_from_export"] is False
    assert observed_workspace_paths[0] not in evidence
    assert json.dumps(observed_workspace_paths[0])[1:-1] not in evidence


def test_unicode_escaped_sample_path_fails_with_safe_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_acceptance_module()
    sample_root = (tmp_path / "非英文样本").resolve()
    sample_root.mkdir()
    evidence_path = tmp_path / "unicode-json-leak.json"
    encoded_path = json.dumps(str(sample_root), ensure_ascii=True)

    def leaking_audit(roots, **kwargs):
        return SimpleNamespace(
            report_json=f'{{"path":{encoded_path}}}',
            report_html="<p>safe</p>",
            findings=(object(),),
            score=SimpleNamespace(coverage=1.0, incomplete=False),
        )

    monkeypatch.setattr(module, "_run_audit", leaking_audit)

    with pytest.raises(RuntimeError, match="^PERSONAL_PRIVACY_ACCEPTANCE_FAILED$"):
        module.run_acceptance(evidence_path, sample_root=sample_root)

    evidence = evidence_path.read_text(encoding="utf-8")
    result = json.loads(evidence)
    assert result["passed"] is False
    assert result["report"]["sample_path_absent_from_json"] is False
    assert result["report"]["sample_path_absent_from_export"] is False
    assert str(sample_root) not in evidence
    assert encoded_path[1:-1] not in evidence


def test_html_entity_workspace_path_fails_with_safe_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_acceptance_module()
    evidence_root = tmp_path / "非英文工作区"
    evidence_root.mkdir()
    evidence_path = evidence_root / "html-entity-leak.json"
    observed_workspace_paths = []
    encoded_paths = []

    def leaking_audit(roots, **kwargs):
        workspace_path = str(Path(roots[0]).parent)
        encoded_path = workspace_path.encode("ascii", "xmlcharrefreplace").decode()
        observed_workspace_paths.append(workspace_path)
        encoded_paths.append(encoded_path)
        return SimpleNamespace(
            report_json="{}",
            report_html=f"<p>{encoded_path}</p>",
            findings=(object(),),
            score=SimpleNamespace(coverage=1.0, incomplete=False),
        )

    monkeypatch.setattr(module, "_run_audit", leaking_audit)

    with pytest.raises(RuntimeError, match="^PERSONAL_PRIVACY_ACCEPTANCE_FAILED$"):
        module.run_acceptance(evidence_path)

    evidence = evidence_path.read_text(encoding="utf-8")
    result = json.loads(evidence)
    assert result["passed"] is False
    assert result["report"]["workspace_path_absent_from_html"] is False
    assert observed_workspace_paths[0] not in evidence
    assert encoded_paths[0] not in evidence


def test_malformed_report_json_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_acceptance_module()
    evidence_path = tmp_path / "malformed-report.json"
    monkeypatch.setattr(
        module,
        "_run_audit",
        lambda *args, **kwargs: SimpleNamespace(
            report_json="{",
            report_html="<p>safe</p>",
            findings=(object(),),
            score=SimpleNamespace(coverage=1.0, incomplete=False),
        ),
    )

    with pytest.raises(RuntimeError, match="^PERSONAL_PRIVACY_ACCEPTANCE_FAILED$"):
        module.run_acceptance(evidence_path)

    result = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert result["passed"] is False
    assert result["report"]["sample_path_absent_from_json"] is False
    assert result["report"]["workspace_path_absent_from_json"] is False


def test_readme_describes_current_personal_privacy_invariants() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    retired_mode = "高敏感" + "模式"
    retired_evidence_term = "readi" + "ness"

    assert retired_mode not in readme
    assert retired_evidence_term not in readme.casefold()
    assert "Personal v1 不支持高敏感现实数据" in readme
    assert "联网分享验证仅在用户显式输入公开 URL 后执行" in readme
