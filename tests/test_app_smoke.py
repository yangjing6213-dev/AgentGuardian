import ast
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone, tzinfo
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QPoint, QRect
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

import agentguardian.app as app_module
from agentguardian.app import COLOR_TOKENS, create_window, export_new_report
from agentguardian.detectors import FileDetectionResult
from agentguardian.discovery import DiscoveryResult
from agentguardian.dispositions import DispositionRecord, DispositionStatus
from agentguardian.domain import Evidence, Finding, RiskDomain, Severity
from agentguardian.evidence_state import (
    EvidenceSnapshot,
    ScanMetadata,
    decode_snapshot,
    encode_snapshot,
)
from agentguardian.state_store import StateStoreError


EVALUATED_AT = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)
DISPOSITION_KEY = b"d" * 32


@pytest.fixture(scope="session")
def qapp():
    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture(autouse=True)
def isolate_local_app_data(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))


def _wait_for_scan(window, application, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while window.is_scanning and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)
    application.processEvents()
    assert not window.is_scanning


def _global_rect(widget) -> QRect:
    return QRect(widget.mapToGlobal(QPoint(0, 0)), widget.size())


def _discovery_result(
    files: tuple[Path, ...], limits: tuple[str, ...] = ()
) -> DiscoveryResult:
    return DiscoveryResult(files=files, limits=limits, entries_seen=len(files))


def _synthetic_finding(index: int, evidence_count: int = 1) -> Finding:
    evidence = tuple(
        Evidence(
            source=f"file-{index}.txt",
            fingerprint=f"{index * 10 + item:064x}",
            masked="masked",
        )
        for item in range(evidence_count)
    )
    return Finding(
        rule_id="TEST_RULE",
        domain=RiskDomain.CREDENTIALS,
        severity=Severity.HIGH,
        root_fingerprint=f"{index:064x}",
        evidence=evidence,
    )


def _state_snapshot(
    schema_version: int,
    *,
    disposition_key: bytes | None = None,
    dispositions: tuple[DispositionRecord, ...] = (),
) -> EvidenceSnapshot:
    return EvidenceSnapshot(
        schema_version=schema_version,
        captured_at="2026-08-02T08:00:00Z",
        product_version="0.1.0",
        rule_version="1.1.0",
        scan=ScanMetadata(1.0, 1.0, False, ()),
        findings=(),
        disposition_key=disposition_key,
        dispositions=dispositions,
    )


def _decoded_v1_snapshot() -> EvidenceSnapshot:
    return decode_snapshot(
        json.dumps(
            {
                "schema_version": 1,
                "captured_at": "2026-08-02T08:00:00Z",
                "product_version": "0.1.0",
                "rule_version": "1.1.0",
                "scan": {
                    "coverage": 1.0,
                    "confidence": 1.0,
                    "incomplete": False,
                    "limits": [],
                },
                "findings": [],
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _disposition(
    finding: Finding,
    status: DispositionStatus,
    *,
    created_at: str = "2026-08-02T08:00:00Z",
    expires_at: str = "2026-08-03T08:00:00Z",
) -> DispositionRecord:
    assert finding.disposition_ref is not None
    return DispositionRecord(
        finding.disposition_ref,
        finding.rule_id,
        status,
        "Synthetic audit review",
        "Local reviewer",
        created_at,
        expires_at,
    )


def test_discovery_limit_marks_audit_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "visible.txt"
    path.write_text("safe", encoding="utf-8")
    monkeypatch.setattr(
        app_module,
        "discover_files",
        lambda *args, **kwargs: SimpleNamespace(
            files=(path,),
            limits=("directory_read_limited",),
            entries_seen=1,
        ),
    )

    outcome = app_module._run_audit(
        (tmp_path,), disposition_key=DISPOSITION_KEY
    )

    assert outcome.score.coverage == 0.5
    assert outcome.score.incomplete is True
    assert "directory_read_limited" in outcome.score.limits


@pytest.mark.parametrize("state", ("v2", "v1", "missing", "invalid"))
def test_window_loads_disposition_context_once_without_writing(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: str,
) -> None:
    stored_key = b"s" * 32
    fresh_key = b"f" * 32
    record = DispositionRecord(
        "a" * 64,
        "OPENAI_API_KEY",
        DispositionStatus.ACCEPTED_RISK,
        "Synthetic accepted risk",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )
    load_calls = []
    fresh_calls = []
    save_calls = []

    def fake_load():
        load_calls.append(None)
        if state == "v2":
            return _state_snapshot(
                2,
                disposition_key=stored_key,
                dispositions=(record,),
            )
        if state == "v1":
            return _decoded_v1_snapshot()
        code = (
            "PROTECTED_STATE_UNAVAILABLE"
            if state == "missing"
            else "PROTECTED_STATE_INVALID"
        )
        raise StateStoreError(code)

    def fake_token_bytes(length: int) -> bytes:
        fresh_calls.append(length)
        return fresh_key

    monkeypatch.setattr(app_module, "load_protected_state", fake_load)
    monkeypatch.setattr(app_module, "save_protected_state", save_calls.append)
    monkeypatch.setattr(app_module.secrets, "token_bytes", fake_token_bytes)
    before = tuple(tmp_path.rglob("*"))

    window = create_window()

    assert load_calls == [None]
    assert save_calls == []
    assert tuple(tmp_path.rglob("*")) == before
    if state == "v2":
        assert window._disposition_key == stored_key
        assert window._dispositions == (record,)
        assert window._dispositions[0] is not record
        assert window._protected_state_invalid is False
        assert fresh_calls == []
    else:
        assert window._disposition_key == fresh_key
        assert window._dispositions == ()
        assert window._protected_state_invalid is (state == "invalid")
        assert fresh_calls == [32]
    assert repr(window._disposition_key) not in repr(window)
    assert "PROTECTED_STATE" not in window.status_label.text()
    window.close()


def test_disposition_context_is_frozen_slotted_and_hides_key() -> None:
    key = b"h" * 32
    context = app_module._DispositionContext(key, (), False)

    assert not hasattr(context, "__dict__")
    assert repr(key) not in repr(context)
    with pytest.raises(FrozenInstanceError):
        context.invalid_state = True


@pytest.mark.parametrize("failure", ("malformed", "unexpected"))
def test_malformed_disposition_state_fails_closed_without_leaking(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    marker = "synthetic-private-state-marker"
    calls = []

    def fake_load():
        calls.append(None)
        if failure == "malformed":
            return SimpleNamespace(
                schema_version=2,
                disposition_key=b"short",
                dispositions=(marker,),
            )
        raise RuntimeError(marker)

    monkeypatch.setattr(app_module, "load_protected_state", fake_load)
    monkeypatch.setattr(app_module.secrets, "token_bytes", lambda length: b"n" * length)

    context = app_module._load_disposition_context()

    assert calls == [None]
    assert context.key == b"n" * 32
    assert context.records == ()
    assert context.invalid_state is True
    assert marker not in repr(context)


@pytest.mark.parametrize("failure", ("type", "length", "exception"))
def test_startup_fresh_key_failure_is_fixed_and_unchained(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    marker = "synthetic-private-startup-key-marker"

    def invalid_token_bytes(length: int):
        assert length == 32
        if failure == "type":
            return bytearray(b"x" * 32)
        if failure == "length":
            return b"x" * 31
        raise RuntimeError(marker)

    monkeypatch.setattr(
        app_module,
        "load_protected_state",
        lambda: (_ for _ in ()).throw(
            StateStoreError("PROTECTED_STATE_UNAVAILABLE")
        ),
    )
    monkeypatch.setattr(app_module.secrets, "token_bytes", invalid_token_bytes)

    with pytest.raises(ValueError, match="^invalid disposition context$") as error:
        app_module._load_disposition_context()

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert marker not in repr(error.value)


@pytest.mark.parametrize("forgery", ("snapshot", "record"))
def test_startup_revalidates_forged_exact_v2_state(
    monkeypatch: pytest.MonkeyPatch,
    forgery: str,
) -> None:
    marker = "synthetic-private-forged-state-marker"
    stored_key = b"s" * 32
    fresh_key = b"f" * 32
    record = DispositionRecord(
        "a" * 64,
        "OPENAI_API_KEY",
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic false positive",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )
    snapshot = _state_snapshot(
        2,
        disposition_key=stored_key,
        dispositions=(record,),
    )
    if forgery == "snapshot":
        object.__setattr__(snapshot, "disposition_key", b"short")
    else:
        object.__setattr__(record, "reason", f"C:\\{marker}")
    load_calls = []

    def load_state():
        load_calls.append(None)
        return snapshot

    monkeypatch.setattr(app_module, "load_protected_state", load_state)
    monkeypatch.setattr(app_module.secrets, "token_bytes", lambda length: fresh_key)

    context = app_module._load_disposition_context()

    assert load_calls == [None]
    assert context.key == fresh_key
    assert context.records == ()
    assert context.invalid_state is True
    assert marker not in repr(context)


@pytest.mark.parametrize(
    ("schema_version", "field"),
    (
        (1, "disposition_key"),
        (1, "dispositions"),
        (2, "captured_at"),
        (2, "product_version"),
        (2, "rule_version"),
        (2, "scan"),
        (2, "findings"),
    ),
)
def test_startup_rejects_forged_snapshot_invariants_without_writing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    schema_version: int,
    field: str,
) -> None:
    marker = "synthetic-private-forged-snapshot-marker"
    stored_key = b"s" * 32
    fresh_key = b"f" * 32
    record = DispositionRecord(
        "a" * 64,
        "OPENAI_API_KEY",
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic false positive",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )
    snapshot = _state_snapshot(
        schema_version,
        disposition_key=stored_key if schema_version == 2 else None,
        dispositions=(record,) if schema_version == 2 else (),
    )
    invalid_values = {
        "disposition_key": marker.encode("ascii"),
        "dispositions": (record,),
        "captured_at": marker,
        "product_version": f"{marker} value",
        "rule_version": f"{marker} value",
        "scan": SimpleNamespace(private=marker),
        "findings": (SimpleNamespace(private=marker),),
    }
    object.__setattr__(snapshot, field, invalid_values[field])
    load_calls = []
    fresh_calls = []
    save_calls = []

    def load_state():
        load_calls.append(None)
        return snapshot

    def fresh_key_value(length: int) -> bytes:
        fresh_calls.append(length)
        return fresh_key

    monkeypatch.setattr(app_module, "load_protected_state", load_state)
    monkeypatch.setattr(app_module, "save_protected_state", save_calls.append)
    monkeypatch.setattr(app_module.secrets, "token_bytes", fresh_key_value)
    before = tuple(tmp_path.rglob("*"))

    context = app_module._load_disposition_context()

    assert load_calls == [None]
    assert fresh_calls == [32]
    assert type(context.key) is bytes
    assert len(context.key) == 32
    assert context.key == fresh_key
    assert context.records == ()
    assert context.invalid_state is True
    assert save_calls == []
    assert tuple(tmp_path.rglob("*")) == before
    assert marker not in repr(context)


def test_window_navigation_trust_strip_and_approved_theme(qapp):
    window = create_window()
    window.resize(window.minimumSize())
    window.show()
    qapp.processEvents()

    assert window.local_mode_label.text() == "本地路径模式"
    assert window.scan_button.text() == "开始审计"
    assert not window.scan_button.icon().isNull()
    assert window.scan_button.toolTip()
    assert [button.text() for button in window.navigation_buttons] == [
        "审计范围",
        "风险发现",
        "审计报告",
    ]
    assert [label.text() for label in window.trust_labels] == [
        "本地路径模式",
        "包源码网络能力：未发现",
        "规则版本：1.1.0",
        "Founder Alpha",
    ]
    assert "映射网络盘" in window.local_mode_label.toolTip()
    assert "依赖" in window.trust_labels[1].toolTip()

    for index, button in enumerate(window.navigation_buttons):
        button.click()
        assert window.stack.currentIndex() == index

    assert not window.protected_state_button.icon().isNull()
    assert not window.protected_state_button.isEnabled()
    report_actions = (
        window.review_button,
        window.protected_state_button,
        window.save_button,
    )
    for left, right in zip(report_actions, report_actions[1:]):
        assert not _global_rect(left).intersects(_global_rect(right))

    assert COLOR_TOKENS == {
        "obsidian": "#0F1215",
        "surface": "#171C20",
        "border": "#394149",
        "cloud": "#F4F6F7",
        "trust": "#21C786",
        "muted": "#AAB4BB",
        "warning": "#F0BD5C",
        "critical": "#EF7167",
    }
    stylesheet = window.styleSheet()
    assert "letter-spacing: 0px" in stylesheet
    assert "gradient" not in stylesheet.lower()
    assert "border-radius: 6px" in stylesheet
    assert window.minimumWidth() >= 960
    assert window.minimumHeight() >= 640
    assert not _global_rect(window.sidebar).intersects(
        _global_rect(window.content_panel)
    )
    assert not _global_rect(window.trust_strip).intersects(_global_rect(window.stack))

    window.close()


def test_openai_local_config_suffixes_are_supported() -> None:
    assert {".env", ".toml"} <= app_module.SUPPORTED_SUFFIXES


def test_openai_env_override_is_masked_end_to_end(qapp, tmp_path: Path) -> None:
    endpoint = "https://synthetic-provider.invalid/v1"
    (tmp_path / ".env").write_text(
        f"export OPENAI_BASE_URL={endpoint}\n",
        encoding="utf-8",
    )

    outcome = app_module._run_audit(
        (tmp_path,), disposition_key=DISPOSITION_KEY
    )

    finding = next(
        item
        for item in outcome.findings
        if item.rule_id == "OPENAI_BASE_URL_OVERRIDE"
    )
    assert finding.evidence[0].masked == "OpenAI API base URL override configured"
    for report in (outcome.report_json, outcome.report_html):
        assert endpoint not in report

    window = create_window()
    window._scan_completed(outcome)
    row = next(
        index
        for index in range(window.findings_table.rowCount())
        if window.findings_table.item(index, 1).text()
        == "OPENAI_BASE_URL_OVERRIDE"
    )
    window.findings_table.selectRow(row)
    qapp.processEvents()
    cells = " ".join(
        window.findings_table.item(row, column).text()
        for column in range(window.findings_table.columnCount())
    )
    assert endpoint not in cells
    assert endpoint not in window.guidance_browser.toPlainText()
    assert "OpenAI" in window.guidance_browser.toPlainText()
    window.close()


def test_cross_scan_dispositions_keep_identity_and_reviewed_score_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    root = Path("first")
    root.mkdir()
    config_path = root / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "synthetic": {
                        "capabilities": {
                            "shell": True,
                            "filesystem_write": True,
                            "network": True,
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    disposition_key = b"d" * 32
    scan_keys = iter(bytes([index]) * 32 for index in range(1, 6))
    file_calls = []
    mcp_calls = []
    real_detect_file = app_module.detect_file
    real_detect_mcp_config = app_module.detect_mcp_config
    monkeypatch.setattr(app_module.secrets, "token_bytes", lambda length: next(scan_keys))

    def capture_file(path, *, scan_key, disposition_key):
        file_calls.append((path, scan_key, disposition_key))
        return real_detect_file(
            path,
            scan_key=scan_key,
            disposition_key=disposition_key,
        )

    def capture_mcp(config, source, *, scan_key, disposition_key):
        mcp_calls.append((source, scan_key, disposition_key))
        return real_detect_mcp_config(
            config,
            source,
            scan_key=scan_key,
            disposition_key=disposition_key,
        )

    monkeypatch.setattr(app_module, "detect_file", capture_file)
    monkeypatch.setattr(app_module, "detect_mcp_config", capture_mcp)

    first = app_module._run_audit(
        (root,),
        disposition_key=disposition_key,
        evaluated_at=EVALUATED_AT,
    )
    first_finding = next(
        finding
        for finding in first.findings
        if finding.rule_id == "MCP_DANGEROUS_COMBINATION"
    )
    saved_record = _disposition(
        first_finding,
        DispositionStatus.FALSE_POSITIVE,
    )
    saved_state = _state_snapshot(
        2,
        disposition_key=disposition_key,
        dispositions=(saved_record,),
    )
    second = app_module._run_audit(
        (root,),
        disposition_key=saved_state.disposition_key,
        dispositions=saved_state.dispositions,
        evaluated_at=EVALUATED_AT,
    )
    second_finding = next(
        finding
        for finding in second.findings
        if finding.rule_id == "MCP_DANGEROUS_COMBINATION"
    )
    first_payload = json.loads(first.report_json)
    second_payload = json.loads(second.report_json)

    assert first_finding.root_fingerprint != second_finding.root_fingerprint
    assert (
        first_payload["findings"][0]["root_hmac_fingerprint"]
        != second_payload["findings"][0]["root_hmac_fingerprint"]
    )
    assert first_finding.disposition_ref == second_finding.disposition_ref
    assert first_finding.evidence[0].source == config_path.name
    assert second.score == first.score
    assert second.score.total == 59
    assert second.score.cap_reason == "mcp_dangerous_combination"
    assert second.reviewed_score.total == 100
    assert second.reviewed_score.cap_reason is None
    assert second_payload["score"]["total"] == second.score.total
    assert second_payload["reviewed_score"]["total"] == second.reviewed_score.total
    assert second_payload["findings"][0]["disposition"]["status"] == "false_positive"
    assert "Disposition status: false_positive" in second.report_html
    assert second.evaluated_at == EVALUATED_AT
    assert not hasattr(second, "__dict__")
    with pytest.raises(FrozenInstanceError):
        second.evaluated_at = datetime.now(timezone.utc)

    accepted = app_module._run_audit(
        (root,),
        disposition_key=disposition_key,
        dispositions=(
            _disposition(first_finding, DispositionStatus.ACCEPTED_RISK),
        ),
        evaluated_at=EVALUATED_AT,
    )
    expired = app_module._run_audit(
        (root,),
        disposition_key=disposition_key,
        dispositions=(
            _disposition(
                first_finding,
                DispositionStatus.FALSE_POSITIVE,
                created_at="2026-08-01T08:00:00Z",
                expires_at="2026-08-02T11:00:00Z",
            ),
        ),
        evaluated_at=EVALUATED_AT,
    )
    assert accepted.reviewed_score == accepted.score
    assert json.loads(accepted.report_json)["findings"][0]["disposition"]["status"] == "accepted_risk"
    assert expired.reviewed_score == expired.score
    assert json.loads(expired.report_json)["findings"][0]["disposition"]["status"] == "expired"

    moved_root = Path("moved")
    moved_root.mkdir()
    moved_path = moved_root / config_path.name
    config_path.replace(moved_path)
    moved = app_module._run_audit(
        (moved_root,),
        disposition_key=disposition_key,
        dispositions=(saved_record,),
        evaluated_at=EVALUATED_AT,
    )
    moved_finding = next(
        finding
        for finding in moved.findings
        if finding.rule_id == "MCP_DANGEROUS_COMBINATION"
    )

    assert moved_finding.disposition_ref != first_finding.disposition_ref
    assert moved.reviewed_score == moved.score
    assert json.loads(moved.report_json)["findings"][0]["disposition"]["status"] == "open"
    assert len({scan_key for _, scan_key, _ in file_calls}) == 5
    assert all(key == disposition_key for _, _, key in file_calls)
    assert all(key == disposition_key for _, _, key in mcp_calls)
    assert [source for source, _, _ in mcp_calls[:4]] == [
        str(config_path.absolute())
    ] * 4
    assert mcp_calls[4][0] == str(moved_path.absolute())
    for report in (second.report_json, second.report_html):
        assert disposition_key.hex() not in report
        assert repr(disposition_key) not in report
        assert first_finding.disposition_ref not in report


def test_audit_freezes_relative_paths_before_cwd_changes_during_mcp_processing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original = tmp_path / "original"
    decoy = tmp_path / "decoy"
    for base, dangerous in ((original, True), (decoy, False)):
        root = base / "relative"
        root.mkdir(parents=True)
        (root / "mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "synthetic": {
                            "capabilities": {
                                "shell": dangerous,
                                "filesystem_write": dangerous,
                                "network": dangerous,
                            }
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
    expected_root = original / "relative"
    expected_file = expected_root / "mcp.json"
    discovered_roots = []
    detected_paths = []
    json_paths = []
    mcp_sources = []
    real_discover = app_module.discover_files
    real_detect_file = app_module.detect_file
    real_read_json = app_module._read_limited_json
    real_detect_mcp = app_module.detect_mcp_config

    def capture_discovery(roots, *args, **kwargs):
        discovered_roots.extend(roots)
        return real_discover(roots, *args, **kwargs)

    def change_cwd_after_detection(path, **kwargs):
        detected_paths.append(path)
        result = real_detect_file(path, **kwargs)
        monkeypatch.chdir(decoy)
        return result

    def capture_json_path(path):
        json_paths.append(path)
        return real_read_json(path)

    def capture_mcp_source(config, source, **kwargs):
        mcp_sources.append(source)
        return real_detect_mcp(config, source, **kwargs)

    monkeypatch.setattr(app_module, "discover_files", capture_discovery)
    monkeypatch.setattr(app_module, "detect_file", change_cwd_after_detection)
    monkeypatch.setattr(app_module, "_read_limited_json", capture_json_path)
    monkeypatch.setattr(app_module, "detect_mcp_config", capture_mcp_source)
    monkeypatch.chdir(original)

    outcome = app_module._run_audit(
        (Path("relative"),),
        disposition_key=DISPOSITION_KEY,
        evaluated_at=EVALUATED_AT,
    )

    assert {finding.rule_id for finding in outcome.findings} == {
        "MCP_DANGEROUS_COMBINATION"
    }
    assert discovered_roots == [expected_root]
    assert outcome.scanned_roots == (expected_root,)
    assert discovered_roots[0] is outcome.scanned_roots[0]
    assert detected_paths == [expected_file]
    assert json_paths[0] is detected_paths[0]
    assert mcp_sources == [str(expected_file)]


@pytest.mark.parametrize("failure", ("type", "length", "exception"))
def test_scan_key_generation_fails_before_discovery_without_leaking(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    marker = "synthetic-private-random-marker"
    calls = []

    def invalid_token_bytes(length: int):
        assert length == 32
        if failure == "type":
            return bytearray(b"x" * 32)
        if failure == "length":
            return b"x" * 31
        raise RuntimeError(marker)

    monkeypatch.setattr(app_module.secrets, "token_bytes", invalid_token_bytes)
    monkeypatch.setattr(
        app_module,
        "discover_files",
        lambda *args, **kwargs: calls.append("discovery"),
    )
    monkeypatch.setattr(
        app_module,
        "detect_file",
        lambda *args, **kwargs: calls.append("detector"),
    )

    with pytest.raises(ValueError, match="^invalid disposition context$") as error:
        app_module._run_audit(
            (tmp_path,),
            disposition_key=DISPOSITION_KEY,
            evaluated_at=EVALUATED_AT,
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert marker not in repr(error.value)
    assert calls == []


def test_worker_maps_scan_key_generation_failure_to_fixed_signal(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker = "synthetic-private-worker-marker"
    failures = []
    worker = app_module.AuditWorker((tmp_path,), DISPOSITION_KEY, ())
    worker.failed.connect(failures.append)
    monkeypatch.setattr(
        app_module.secrets,
        "token_bytes",
        lambda length: (_ for _ in ()).throw(RuntimeError(marker)),
    )

    worker.run()

    assert failures == ["scan_failed"]
    assert marker not in repr(failures)


def test_disposition_context_validation_consumes_once_without_length_hint() -> None:
    records = (
        DispositionRecord(
            reference * 64,
            "OPENAI_API_KEY",
            DispositionStatus.ACCEPTED_RISK,
            "Synthetic accepted risk",
            "Local reviewer",
            "2026-08-02T08:00:00Z",
            "2026-08-03T08:00:00Z",
        )
        for reference in ("b", "a")
    )
    original = tuple(records)

    class OneShotRecords:
        def __init__(self):
            self.iterations = 0
            self.length_calls = 0

        def __iter__(self):
            self.iterations += 1
            if self.iterations > 1:
                raise AssertionError("iterated twice")
            return iter(original)

        def __len__(self):
            self.length_calls += 1
            raise AssertionError("length hint requested")

    values = OneShotRecords()

    context = app_module._validated_disposition_context(DISPOSITION_KEY, values)

    assert context.key == DISPOSITION_KEY
    assert tuple(record.disposition_ref for record in context.records) == (
        "a" * 64,
        "b" * 64,
    )
    assert all(
        rebuilt is not source
        for rebuilt, source in zip(context.records, reversed(original))
    )
    assert values.iterations == 1
    assert values.length_calls == 0


@pytest.mark.parametrize(
    "failure",
    ("key", "naive_time", "hostile_time", "time_subclass", "record", "overflow", "iterator"),
)
def test_invalid_audit_context_stops_before_randomness_and_callbacks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    marker = "synthetic-private-context-marker"
    token_calls = []
    callbacks = []
    valid_record = DispositionRecord(
        "a" * 64,
        "OPENAI_API_KEY",
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic false positive",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )

    class HostileTimezone(tzinfo):
        def utcoffset(self, value):
            raise RuntimeError(marker)

    class DatetimeSubclass(datetime):
        pass

    class OverflowingRecords:
        def __init__(self):
            self.iterations = 0
            self.length_calls = 0

        def __iter__(self):
            self.iterations += 1
            for _index in range(app_module.MAX_AUDIT_FINDINGS + 1):
                yield valid_record

        def __len__(self):
            self.length_calls += 1
            raise RuntimeError(marker)

    class ExplodingRecords:
        def __init__(self):
            self.iterations = 0

        def __iter__(self):
            self.iterations += 1
            yield valid_record
            raise RuntimeError(marker)

    key = DISPOSITION_KEY
    evaluated_at = EVALUATED_AT
    dispositions = ()
    tracked = None
    if failure == "key":
        key = b"short"
    elif failure == "naive_time":
        evaluated_at = datetime(2026, 8, 2, 12, 0)
    elif failure == "hostile_time":
        evaluated_at = datetime(2026, 8, 2, 12, 0, tzinfo=HostileTimezone())
    elif failure == "time_subclass":
        evaluated_at = DatetimeSubclass(2026, 8, 2, 12, 0, tzinfo=timezone.utc)
    elif failure == "record":
        object.__setattr__(valid_record, "reason", f"C:\\{marker}")
        dispositions = (valid_record,)
    elif failure == "overflow":
        tracked = OverflowingRecords()
        dispositions = tracked
    else:
        tracked = ExplodingRecords()
        dispositions = tracked

    def token_bytes(length: int) -> bytes:
        token_calls.append(length)
        return b"s" * 32

    monkeypatch.setattr(app_module.secrets, "token_bytes", token_bytes)
    monkeypatch.setattr(
        app_module,
        "discover_files",
        lambda *args, **kwargs: callbacks.append("discovery")
        or _discovery_result(()),
    )
    monkeypatch.setattr(
        app_module,
        "detect_file",
        lambda *args, **kwargs: callbacks.append("file"),
    )
    monkeypatch.setattr(
        app_module,
        "detect_mcp_config",
        lambda *args, **kwargs: callbacks.append("mcp"),
    )

    with pytest.raises(ValueError, match="^invalid disposition context$") as error:
        app_module._run_audit(
            (tmp_path,),
            disposition_key=key,
            dispositions=dispositions,
            evaluated_at=evaluated_at,
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert marker not in repr(error.value)
    assert token_calls == []
    assert callbacks == []
    if failure == "overflow":
        assert tracked.iterations == 1
        assert tracked.length_calls == 0
    elif failure == "iterator":
        assert tracked.iterations == 1


def test_openai_finding_uses_openai_manual_guidance(qapp) -> None:
    finding = Finding(
        rule_id="OPENAI_API_KEY",
        domain=RiskDomain.CREDENTIALS,
        severity=Severity.HIGH,
        root_fingerprint="a" * 64,
        evidence=(Evidence("settings.env", "a" * 64, "sk-p************wxyz"),),
    )
    window = create_window()

    window._populate_findings((finding,))
    window.findings_table.selectRow(0)
    qapp.processEvents()

    guidance = window.guidance_browser.toPlainText().lower()
    assert "openai" in guidance
    assert "revoke" in guidance
    window.close()


def test_protected_state_is_saved_only_after_explicit_action(
    qapp, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = "synthetic-state-marker"
    (tmp_path / "private.env").write_text(
        f"OPENAI_API_KEY=sk-proj-{marker}-123456789\n",
        encoding="utf-8",
    )
    saved = []
    messages = []
    warnings = []
    monkeypatch.setattr(
        app_module,
        "save_protected_state",
        lambda snapshot: saved.append(snapshot),
    )
    monkeypatch.setattr(
        QMessageBox,
        "information",
        lambda parent, title, message: messages.append((title, message)),
    )
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    window = create_window()

    assert not window.protected_state_button.isEnabled()
    assert saved == []
    outcome = app_module._run_audit(
        (tmp_path,), disposition_key=DISPOSITION_KEY
    )
    assert saved == []

    window._scan_completed(outcome)
    assert window.protected_state_button.isEnabled()
    assert saved == []

    window.protected_state_button.click()

    assert len(saved) == 1
    assert type(window._disposition_key) is bytes
    assert len(window._disposition_key) == 32
    assert window._dispositions == ()
    snapshot = saved[0]
    assert snapshot.schema_version == 2
    assert snapshot.disposition_key == window._disposition_key
    assert type(snapshot.disposition_key) is bytes
    assert len(snapshot.disposition_key) == 32
    assert snapshot.dispositions == ()
    assert repr(snapshot.disposition_key) not in repr(snapshot)
    encoded = encode_snapshot(snapshot)
    assert decode_snapshot(encoded) == snapshot
    assert marker.encode() not in encoded
    assert b"private.env" not in encoded
    assert str(tmp_path).encode() not in encoded
    assert warnings == []
    assert messages == [("保存完成", "加密状态已保存到当前 Windows 用户。")]
    window.close()


def test_normal_audit_lifecycle_never_saves_protected_state(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "audit-root"
    root.mkdir()
    (root / "safe.txt").write_text("safe", encoding="utf-8")
    local_app_data = Path(os.environ["LOCALAPPDATA"])
    protected_saves = []
    worker_context = {}
    real_worker = app_module.AuditWorker

    class CapturingWorker(real_worker):
        def __init__(self, roots, disposition_key, dispositions):
            super().__init__(roots, disposition_key, dispositions)
            worker_context.update(
                roots=self._roots,
                disposition_key=self._disposition_key,
                dispositions=self._dispositions,
                representation=repr(self),
            )

    monkeypatch.setattr(app_module, "AuditWorker", CapturingWorker)
    monkeypatch.setattr(app_module, "save_protected_state", protected_saves.append)
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(root),
    )
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *args, **kwargs: (str(tmp_path / "report.json"), "JSON (*.json)"),
    )
    monkeypatch.setattr(app_module, "export_new_report", lambda *args: None)
    monkeypatch.setattr(QMessageBox, "information", lambda *args: None)

    window = create_window()
    assert protected_saves == []
    assert not local_app_data.exists()

    window.folder_button.click()
    assert protected_saves == []
    window.scan_button.click()
    assert worker_context["roots"] == (root,)
    assert worker_context["disposition_key"] == window._disposition_key
    assert type(worker_context["dispositions"]) is tuple
    assert repr(window._disposition_key) not in worker_context["representation"]
    assert protected_saves == []

    _wait_for_scan(window, qapp)
    assert protected_saves == []
    window.report_mode_combo.setCurrentText("JSON")
    window._refresh_report()
    assert protected_saves == []
    window.save_button.click()
    assert protected_saves == []
    assert not local_app_data.exists()
    window.close()


def test_protected_state_failure_uses_fixed_safe_message(
    qapp, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "safe.txt").write_text("safe", encoding="utf-8")
    outcome = app_module._run_audit(
        (tmp_path,), disposition_key=DISPOSITION_KEY
    )
    messages = []
    marker = "synthetic-private-path-marker"
    monkeypatch.setattr(
        app_module,
        "save_protected_state",
        lambda snapshot: (_ for _ in ()).throw(StateStoreError(marker)),
    )
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: messages.append((title, message)),
    )
    window = create_window()
    window._scan_completed(outcome)

    window.protected_state_button.click()

    assert messages == [("保存失败", "无法保存加密状态。")]
    assert marker not in repr(messages)
    window._invalidate_report()
    assert not window.protected_state_button.isEnabled()
    window.close()


def test_non_openai_finding_keeps_generic_manual_guidance(qapp) -> None:
    finding = Finding(
        rule_id="GENERIC_API_KEY",
        domain=RiskDomain.CREDENTIALS,
        severity=Severity.HIGH,
        root_fingerprint="b" * 64,
        evidence=(Evidence("settings.env", "b" * 64, "g********h"),),
    )
    window = create_window()

    window._populate_findings((finding,))
    window.findings_table.selectRow(0)
    qapp.processEvents()

    guidance = window.guidance_browser.toPlainText().lower()
    assert "generic provider" in guidance
    assert "openai" not in guidance
    window.close()


def test_folder_selection_shows_only_short_name(qapp, monkeypatch, tmp_path):
    selected = tmp_path / "selected-root"
    selected.mkdir()
    window = create_window()
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(selected),
    )

    window.folder_button.click()

    assert window.root_display_label.text() == "selected-root"
    assert str(selected) not in window.root_display_label.text()
    assert window.scan_button.isEnabled()
    window.close()


def test_unc_paths_are_rejected_before_filesystem_access(monkeypatch):
    unc_root = Path(r"\\synthetic-server\private-share")
    monkeypatch.setattr(
        app_module,
        "_is_reparse",
        lambda path: pytest.fail("UNC path reached filesystem inspection"),
    )
    monkeypatch.setattr(
        app_module,
        "discover_files",
        lambda *args, **kwargs: pytest.fail("UNC path reached discovery"),
    )

    assert app_module._is_unc_path(unc_root)
    assert not app_module._is_unc_path(Path(r"C:\local"))
    with pytest.raises(ValueError, match="UNC"):
        export_new_report(unc_root / "report.json", "unsafe", [])
    with pytest.raises(ValueError, match="UNC"):
        app_module._run_audit((unc_root,), disposition_key=DISPOSITION_KEY)


def test_folder_selection_rejects_unc_root(qapp, monkeypatch):
    window = create_window()
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: r"\\synthetic-server\private-share",
    )

    window.folder_button.click()

    assert window._roots == ()
    assert not window.scan_button.isEnabled()
    assert "UNC" in window.status_label.text()
    assert "映射网络盘" in window.status_label.text()
    window.close()


def test_selecting_new_root_invalidates_old_report_and_findings(
    qapp, monkeypatch, tmp_path
):
    selected = tmp_path / "new-root"
    selected.mkdir()
    window = create_window()
    window.report_json = "old json"
    window.report_html = "old html"
    window._report_roots = (tmp_path / "old-root",)
    window.findings_table.setRowCount(1)
    window.guidance_browser.setPlainText("old guidance")
    window.save_button.setEnabled(True)
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(selected),
    )

    window.folder_button.click()

    assert window.report_json == ""
    assert window.report_html == ""
    assert window._report_roots == ()
    assert window.findings_table.rowCount() == 0
    assert "old guidance" not in window.guidance_browser.toPlainText()
    assert not window.save_button.isEnabled()
    window.close()


def test_export_uses_roots_that_produced_report(qapp, monkeypatch, tmp_path):
    report_root = tmp_path / "report-root"
    current_root = tmp_path / "current-root"
    report_root.mkdir()
    current_root.mkdir()
    outcome = app_module._run_audit(
        (report_root,), disposition_key=DISPOSITION_KEY
    )
    window = create_window()
    window._scan_completed(outcome)
    window._roots = (current_root,)
    captured = {}
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *args, **kwargs: (str(tmp_path / "report.html"), "HTML"),
    )
    monkeypatch.setattr(
        app_module,
        "export_new_report",
        lambda path, content, roots: captured.update(roots=tuple(roots)),
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)

    window._export_report()

    assert captured["roots"] == (report_root,)
    window.close()


def test_threaded_worker_scans_synthetic_root_without_leaking_raw_data(
    qapp, monkeypatch, tmp_path
):
    root = tmp_path / "synthetic-audit-root"
    root.mkdir()
    raw_secret = "".join(  # noqa: FLY002 - keep secret synthetic at runtime
        ("sk", "-", "proj", "-", "Task7Runtime", "Secret123456789")
    )
    (root / "agent.json").write_text(
        json.dumps(
            {
                "api_key": raw_secret,
                "mcpServers": {
                    "local": {
                        "capabilities": {
                            "shell": True,
                            "filesystem_write": True,
                            "network": True,
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (root / "ignored.py").write_text(raw_secret, encoding="utf-8")
    window = create_window()
    window.show()
    qapp.processEvents()
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(root),
    )

    window.folder_button.click()
    window.scan_button.click()
    assert window.is_scanning
    assert not window.scan_button.isEnabled()
    assert window.scan_button.text() == "审计中..."
    _wait_for_scan(window, qapp)

    payload = json.loads(window.report_json)
    assert payload["score"]["coverage"] == 1.0
    assert payload["score"]["incomplete"] is False
    assert {item["rule_id"] for item in payload["findings"]} >= {
        "OPENAI_API_KEY",
        "MCP_DANGEROUS_COMBINATION",
    }
    for report in (window.report_json, window.report_html):
        assert raw_secret not in report
        assert str(root) not in report
    for row in range(window.findings_table.rowCount()):
        cells = [
            window.findings_table.item(row, column).text()
            for column in range(window.findings_table.columnCount())
        ]
        assert raw_secret not in " ".join(cells)
        assert str(root) not in " ".join(cells)

    assert window.scan_button.isEnabled()
    assert window.scan_button.text() == "开始审计"
    assert "完成" in window.status_label.text()
    assert window.findings_table.rowCount() >= 2
    window.findings_table.selectRow(0)
    window.navigation_buttons[2].click()
    window.review_button.click()
    assert window.stack.currentIndex() == 1
    assert window.findings_table.hasFocus()
    assert window.guidance_browser.toPlainText().strip()

    window.navigation_buttons[2].click()
    window.report_mode_combo.setCurrentText("JSON")
    assert '"product": "AgentGuardian"' in window.report_browser.toPlainText()
    assert not window.save_button.icon().isNull()
    window.close()


def test_no_supported_files_produces_incomplete_zero_coverage(
    qapp, monkeypatch, tmp_path
):
    root = tmp_path / "unsupported-only"
    root.mkdir()
    (root / "tool.py").write_text("print('not scanned')", encoding="utf-8")
    window = create_window()
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(root),
    )

    window.folder_button.click()
    window.scan_button.click()
    _wait_for_scan(window, qapp)

    payload = json.loads(window.report_json)
    assert payload["score"]["coverage"] == 0.0
    assert payload["score"]["incomplete"] is True
    assert payload["score"]["limits"] == ["no_supported_files"]
    assert window.findings_table.rowCount() == 0
    assert "审计未完整" in window.status_label.text()
    assert "覆盖率 0%" in window.status_label.text()
    assert "不能判定为安全" in window.status_label.text()
    window.close()


def test_audit_finding_cap_stops_remaining_files_and_uses_complete_coverage(
    qapp, monkeypatch, tmp_path
):
    files = tuple(tmp_path / name for name in ("a.txt", "b.txt", "c.txt"))
    for path in files:
        path.write_text("x", encoding="utf-8")
    batches = {
        files[0]: (_synthetic_finding(1),),
        files[1]: (_synthetic_finding(2), _synthetic_finding(3)),
        files[2]: (_synthetic_finding(4),),
    }
    calls = []
    monkeypatch.setattr(app_module, "MAX_AUDIT_FINDINGS", 2)
    monkeypatch.setattr(app_module, "MAX_AUDIT_EVIDENCE", 10)
    monkeypatch.setattr(
        app_module,
        "discover_files",
        lambda roots, suffixes, *, max_files, max_entries: _discovery_result(files),
    )

    def fake_detect_file(path, *, scan_key, disposition_key):
        calls.append(path)
        return FileDetectionResult(batches[path], True, ())

    monkeypatch.setattr(app_module, "detect_file", fake_detect_file)

    outcome = app_module._run_audit(
        (tmp_path,), disposition_key=DISPOSITION_KEY
    )

    assert calls == list(files[:2])
    assert len(outcome.findings) == 2
    assert outcome.score.coverage == pytest.approx(1 / 3)
    assert outcome.score.limits == ("finding_limit_reached",)
    assert outcome.score.incomplete is True
    window = create_window()
    window._scan_completed(outcome)
    assert "审计未完整" in window.status_label.text()
    assert "发现 2 项风险" in window.status_label.text()
    assert "覆盖率 33%" in window.status_label.text()
    assert "不能判定为安全" in window.status_label.text()
    window.close()


def test_audit_evidence_cap_rejects_partial_finding_batch(monkeypatch, tmp_path):
    files = tuple(tmp_path / name for name in ("a.txt", "b.txt", "c.txt"))
    for path in files:
        path.write_text("x", encoding="utf-8")
    batches = {
        files[0]: (_synthetic_finding(1),),
        files[1]: (_synthetic_finding(2, evidence_count=2),),
        files[2]: (_synthetic_finding(3),),
    }
    calls = []
    monkeypatch.setattr(app_module, "MAX_AUDIT_FINDINGS", 10)
    monkeypatch.setattr(app_module, "MAX_AUDIT_EVIDENCE", 2)
    monkeypatch.setattr(
        app_module,
        "discover_files",
        lambda roots, suffixes, *, max_files, max_entries: _discovery_result(files),
    )

    def fake_detect_file(path, *, scan_key, disposition_key):
        calls.append(path)
        return FileDetectionResult(batches[path], True, ())

    monkeypatch.setattr(app_module, "detect_file", fake_detect_file)

    outcome = app_module._run_audit(
        (tmp_path,), disposition_key=DISPOSITION_KEY
    )

    assert calls == list(files[:2])
    assert outcome.findings == batches[files[0]]
    assert outcome.score.coverage == pytest.approx(1 / 3)
    assert outcome.score.limits == ("finding_limit_reached",)
    assert outcome.score.incomplete is True


def test_discovery_file_sentinel_marks_scan_incomplete(monkeypatch, tmp_path):
    files = tuple(tmp_path / name for name in ("a.txt", "b.txt", "c.txt"))
    for path in files:
        path.write_text("x", encoding="utf-8")
    calls = []
    monkeypatch.setattr(app_module, "MAX_AUDIT_FILES", 2)

    def fake_discover(roots, suffixes, *, max_files, max_entries):
        assert max_files == 2
        return _discovery_result(files[:2], ("file_limit_reached",))

    def fake_detect_file(path, *, scan_key, disposition_key):
        calls.append(path)
        return FileDetectionResult((), True, ())

    monkeypatch.setattr(app_module, "discover_files", fake_discover)
    monkeypatch.setattr(app_module, "detect_file", fake_detect_file)

    outcome = app_module._run_audit(
        (tmp_path,), disposition_key=DISPOSITION_KEY
    )

    assert calls == list(files[:2])
    assert outcome.score.coverage == pytest.approx(2 / 3)
    assert outcome.score.limits == ("file_limit_reached",)
    assert outcome.score.incomplete is True


def test_total_byte_limit_stops_before_over_budget_file(monkeypatch, tmp_path):
    files = tuple(tmp_path / name for name in ("a.txt", "b.txt", "c.txt"))
    for path in files:
        path.write_bytes(b"abc")
    calls = []
    monkeypatch.setattr(app_module, "MAX_AUDIT_FILES", 10)
    monkeypatch.setattr(app_module, "MAX_AUDIT_BYTES", 5)
    monkeypatch.setattr(
        app_module,
        "discover_files",
        lambda roots, suffixes, *, max_files, max_entries: _discovery_result(files),
    )

    def fake_detect_file(path, *, scan_key, disposition_key):
        calls.append(path)
        return FileDetectionResult((), True, ())

    monkeypatch.setattr(app_module, "detect_file", fake_detect_file)

    outcome = app_module._run_audit(
        (tmp_path,), disposition_key=DISPOSITION_KEY
    )

    assert calls == [files[0]]
    assert outcome.score.coverage == pytest.approx(1 / 3)
    assert outcome.score.limits == ("byte_limit_reached",)
    assert outcome.score.incomplete is True


def test_json_config_reader_is_bounded(monkeypatch, tmp_path):
    path = tmp_path / "agent.json"
    path.write_bytes(b'{"mcpServers": {}}')
    monkeypatch.setattr(app_module, "MAX_FILE_BYTES", 8)

    with pytest.raises(ValueError, match="JSON file limit"):
        app_module._read_limited_json(path)


def test_duplicate_findings_are_aggregated_once(monkeypatch, tmp_path):
    path = tmp_path / "a.txt"
    path.write_text("x", encoding="utf-8")
    finding = _synthetic_finding(1)
    monkeypatch.setattr(
        app_module,
        "discover_files",
        lambda roots, suffixes, *, max_files, max_entries: _discovery_result((path,)),
    )
    monkeypatch.setattr(
        app_module,
        "detect_file",
        lambda path, *, scan_key, disposition_key: FileDetectionResult(
            (finding, finding), True, ()
        ),
    )

    outcome = app_module._run_audit(
        (tmp_path,), disposition_key=DISPOSITION_KEY
    )

    assert outcome.findings == (finding,)
    assert len(json.loads(outcome.report_json)["findings"]) == 1


def test_export_new_report_is_exclusive_and_outside_scanned_roots(tmp_path):
    scanned_root = tmp_path / "scanned"
    export_root = tmp_path / "exports"
    scanned_root.mkdir()
    export_root.mkdir()
    destination = export_root / "report.json"

    export_new_report(destination, "safe report", [scanned_root])
    assert destination.read_text(encoding="utf-8") == "safe report"

    with pytest.raises(FileExistsError):
        export_new_report(destination, "replacement", [scanned_root])
    with pytest.raises(ValueError, match="scanned root"):
        export_new_report(scanned_root / "report.json", "unsafe", [scanned_root])
    with pytest.raises(FileNotFoundError):
        export_new_report(tmp_path / "missing" / "report.json", "unsafe", [])
    assert "stable destination directory" in export_new_report.__doc__
    assert "reparse" in export_new_report.__doc__.lower()


def test_export_rejects_resolved_parent_symlink_into_scanned_root(tmp_path):
    scanned_root = tmp_path / "scanned"
    scanned_root.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(scanned_root, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"directory symlink unavailable: {error.__class__.__name__}")

    destination = linked_parent / "report.json"
    with pytest.raises(ValueError, match="scanned root"):
        export_new_report(destination, "unsafe", [scanned_root])
    assert not (scanned_root / "report.json").exists()


def test_export_rejects_dangling_final_component_symlink(tmp_path):
    export_root = tmp_path / "exports"
    export_root.mkdir()
    destination = export_root / "report.json"
    missing_target = tmp_path / "missing-target.json"
    try:
        destination.symlink_to(missing_target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"file symlink unavailable: {error.__class__.__name__}")

    with pytest.raises(ValueError, match="reparse"):
        export_new_report(destination, "unsafe", [])
    assert not missing_target.exists()


def test_window_refuses_close_while_worker_is_running(qapp):
    class RunningThread:
        def isRunning(self):
            return True

        def quit(self):
            pass

        def wait(self, _milliseconds):
            return False

    window = create_window()
    window._thread = RunningThread()
    event = QCloseEvent()

    window.closeEvent(event)

    assert not event.isAccepted()
    assert window.status_label.text() == "审计仍在进行，请等待完成。"
    window._thread = None


def test_scan_failure_clears_old_report_and_findings(qapp, tmp_path):
    window = create_window()
    window.report_json = "old json"
    window.report_html = "old html"
    window._report_roots = (tmp_path,)
    window.findings_table.setRowCount(1)
    window.guidance_browser.setPlainText("old guidance")
    window.save_button.setEnabled(True)

    window._scan_failed("fixed_code")

    assert window.report_json == ""
    assert window.report_html == ""
    assert window._report_roots == ()
    assert window.findings_table.rowCount() == 0
    assert "old guidance" not in window.guidance_browser.toPlainText()
    assert not window.save_button.isEnabled()


def test_production_modules_have_no_dangerous_capabilities_and_one_write_site():
    project_root = Path(__file__).resolve().parents[1]
    production_paths = [
        project_root / "src" / "agentguardian" / "app.py",
        project_root / "src" / "agentguardian" / "__main__.py",
    ]
    banned_imports = {
        "http",
        "requests",
        "socket",
        "subprocess",
        "urllib",
        "webbrowser",
        "pyperclip",
    }
    writes = []

    for path in production_paths:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert (
                    not {item.name.split(".")[0] for item in node.names}
                    & banned_imports
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in banned_imports
            elif isinstance(node, ast.Attribute):
                assert node.attr not in {"clipboard", "write_bytes", "write_text"}
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "open"
            ):
                mode = (
                    node.args[1]
                    if len(node.args) > 1
                    else next(
                        (
                            keyword.value
                            for keyword in node.keywords
                            if keyword.arg == "mode"
                        ),
                        None,
                    )
                )
                if isinstance(mode, ast.Constant) and any(
                    flag in mode.value for flag in "wax+"
                ):
                    parent = node
                    while parent and not isinstance(
                        parent, (ast.FunctionDef, ast.AsyncFunctionDef)
                    ):
                        parent = parents.get(parent)
                    writes.append((parent.name, mode.value))

    app_source = production_paths[0].read_text(encoding="utf-8")
    assert "secrets.token_bytes(32)" in app_source
    assert writes == [("export_new_report", "x")]
