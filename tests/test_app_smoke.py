import ast
import inspect
import json
import os
import time
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import (
    QDate,
    QDateTime,
    QPoint,
    QRect,
    Qt,
    QTime,
    QTimer,
    QTimeZone,
)
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QWidget,
)

import agentguardian.app as app_module
from agentguardian.app import COLOR_TOKENS, create_window, export_new_report
from agentguardian.detectors import FileDetectionResult
from agentguardian.discovery import DiscoveryResult
from agentguardian.dispositions import (
    DispositionRecord,
    DispositionStatus,
    disposition_index,
    reviewed_findings,
)
from agentguardian.domain import (
    MAX_REPORT_EVIDENCE,
    MAX_REPORT_FINDINGS,
    Evidence,
    Finding,
    RiskDomain,
    Severity,
)
from agentguardian.evidence_state import (
    EvidenceReference,
    EvidenceSnapshot,
    FindingReference,
    ScanMetadata,
    decode_snapshot,
    encode_snapshot,
)
from agentguardian.report_comparison import ReportSummary, compare_report_summaries
from agentguardian.reporting import render_html, render_json
from agentguardian.scoring import score
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


def _approve_current_scope(window) -> None:
    window.supported_data_checkbox.setChecked(True)
    assert window.supported_data_checkbox.isChecked()
    window.scope_consent_checkbox.setChecked(True)
    assert window.scope_consent_checkbox.isChecked()
    assert window.scan_button.isEnabled()


def _run_audit(
    roots: tuple[Path, ...],
    **kwargs: object,
) -> app_module.AuditOutcome:
    normalized_roots = tuple(Path(os.path.abspath(root)) for root in roots)
    return app_module._run_audit(
        roots,
        scope_preview=app_module._scope_preview_for(normalized_roots),
        **kwargs,
    )


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
    findings: tuple[FindingReference, ...] = (),
    disposition_key: bytes | None = None,
    dispositions: tuple[DispositionRecord, ...] = (),
) -> EvidenceSnapshot:
    return EvidenceSnapshot(
        schema_version=schema_version,
        captured_at="2026-08-02T08:00:00Z",
        product_version="0.1.0",
        rule_version="1.1.0",
        scan=ScanMetadata(1.0, 1.0, False, ()),
        findings=findings,
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


def _disposition_finding(index: int = 1) -> Finding:
    return Finding(
        rule_id="GENERIC_API_KEY",
        domain=RiskDomain.CREDENTIALS,
        severity=Severity.HIGH,
        root_fingerprint=f"{index:064x}",
        evidence=(Evidence(f"file-{index}.txt", f"{index + 1:064x}", "masked"),),
        disposition_ref=f"{index + 2:064x}",
    )


def _audit_outcome(
    findings: tuple[Finding, ...],
    records: tuple[DispositionRecord, ...] = (),
    *,
    evaluated_at: datetime = EVALUATED_AT,
    coverage: float = 0.75,
    confidence: float = 0.8,
    limits: tuple[str, ...] = ("file_scan_limited",),
) -> app_module.AuditOutcome:
    technical = score(
        findings,
        coverage=coverage,
        confidence=confidence,
        limits=limits,
    )
    reviewed = score(
        reviewed_findings(
            findings,
            disposition_index(records),
            now=evaluated_at,
        ),
        coverage=technical.coverage,
        confidence=technical.confidence,
        limits=technical.limits,
    )
    return app_module.AuditOutcome(
        findings=findings,
        score=technical,
        reviewed_score=reviewed,
        evaluated_at=evaluated_at,
        rule_version="1.1.0",
        report_json=render_json(
            technical,
            findings,
            rule_version="1.1.0",
            reviewed_score=reviewed,
            dispositions=records,
            evaluated_at=evaluated_at,
        ),
        report_html=render_html(
            technical,
            findings,
            rule_version="1.1.0",
            reviewed_score=reviewed,
            dispositions=records,
            evaluated_at=evaluated_at,
        ),
        scanned_roots=(Path(r"C:\private\audit-root"),),
    )


def _window_transaction_state(window) -> tuple[object, ...]:
    return (
        window._dispositions,
        window._protected_state_invalid,
        window._audit_outcome,
        window.report_json,
        window.report_html,
        window.report_browser.toPlainText(),
        window.report_browser.toHtml(),
        window._report_roots,
        window.guidance_browser.toPlainText(),
        window.status_label.text(),
        window._refresh_failure_notified,
        window._expiry_timer.isActive(),
        window._expiry_timer.interval(),
        (
            window.false_positive_button.isEnabled(),
            window.accepted_risk_button.isEnabled(),
            window.withdraw_button.isEnabled(),
        ),
        window.findings_table.currentRow(),
        (
            window.findings_table.currentIndex().row(),
            window.findings_table.currentIndex().column(),
        ),
        tuple(
            (index.row(), index.column())
            for index in window.findings_table.selectedIndexes()
        ),
        tuple(
            tuple(
                window.findings_table.item(row, column).text()
                for column in range(window.findings_table.columnCount())
            )
            for row in range(window.findings_table.rowCount())
        ),
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

    outcome = _run_audit(
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


@pytest.mark.parametrize(
    ("schema_version", "forgery"),
    (
        (2, "scan_coverage"),
        (2, "scan_limits"),
        (2, "finding_root"),
        (2, "finding_rule"),
        (2, "finding_order"),
        (2, "evidence_fingerprint"),
        (2, "evidence_masked"),
        (1, "evidence_masked"),
    ),
)
def test_startup_rejects_forged_nested_snapshot_without_writing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    schema_version: int,
    forgery: str,
) -> None:
    marker = "synthetic-private-forged-nested-marker"
    stored_key = b"s" * 32
    fresh_key = b"f" * 32
    evidence = (
        EvidenceReference("a" * 64, "OpenAI API key detected"),
        EvidenceReference("b" * 64, "OpenAI API key detected"),
    )
    finding = FindingReference(
        "OPENAI_API_KEY",
        "c" * 64,
        evidence,
    )
    snapshot = _state_snapshot(
        schema_version,
        findings=(finding,),
        disposition_key=stored_key if schema_version == 2 else None,
    )
    target, field, invalid_value = {
        "scan_coverage": (snapshot.scan, "coverage", 2.0),
        "scan_limits": (snapshot.scan, "limits", (marker,)),
        "finding_root": (finding, "root_hmac_fingerprint", marker),
        "finding_rule": (finding, "rule_id", marker),
        "finding_order": (finding, "evidence", tuple(reversed(evidence))),
        "evidence_fingerprint": (evidence[0], "hmac_fingerprint", marker),
        "evidence_masked": (evidence[0], "masked", f"C:\\{marker}"),
    }[forgery]
    object.__setattr__(target, field, invalid_value)
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
    assert "b" * 64 not in repr(context)


def test_personal_navigation_trust_strip_and_approved_theme(qapp):
    window = create_window()
    window.resize(window.minimumSize())
    window.show()
    qapp.processEvents()

    assert window.stack.count() == 3
    assert window.local_mode_label.text() == "本地路径模式"
    assert window.scan_button.text() == "开始审计"
    assert not window.scan_button.icon().isNull()
    assert window.scan_button.toolTip()
    assert [button.text() for button in window.navigation_buttons] == [
        "审计范围",
        "风险发现",
        "审计报告",
    ]
    assert len(window.navigation_buttons) == 3
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
    assert not hasattr(window, "control_plane_status_label")
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

def test_report_page_comparison_controls_and_valid_aggregate_flow(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    baseline_finding = Finding(
        "BASELINE_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "1" * 64,
        (Evidence("baseline.env", "2" * 64, "masked-baseline"),),
        "3" * 64,
    )
    baseline_record = _disposition(
        baseline_finding,
        DispositionStatus.FALSE_POSITIVE,
    )
    baseline = _audit_outcome(
        (baseline_finding,),
        (baseline_record,),
        coverage=1.0,
        confidence=1.0,
        limits=(),
    )
    current_findings = (
        Finding(
            "ALPHA_RULE",
            RiskDomain.CREDENTIALS,
            Severity.HIGH,
            "4" * 64,
            (Evidence("alpha.env", "5" * 64, "masked-alpha"),),
            "6" * 64,
        ),
        Finding(
            "ZETA_RULE",
            RiskDomain.RETENTION,
            Severity.LOW,
            "7" * 64,
            (Evidence("zeta.env", "8" * 64, "masked-zeta"),),
            "9" * 64,
        ),
    )
    current_record = _disposition(
        current_findings[1],
        DispositionStatus.ACCEPTED_RISK,
    )
    baseline_path = tmp_path / "baseline-report.json"
    baseline_path.write_text(baseline.report_json, encoding="utf-8")
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *args, **kwargs: (str(baseline_path), "JSON (*.json)"),
    )

    window = create_window()
    assert not window.comparison_select_button.isEnabled()
    assert not window.comparison_clear_button.isEnabled()
    assert window.baseline_name_label.text() == "基线：未选择"

    current = _audit_outcome(current_findings, (current_record,))
    window._scan_completed(current)
    assert window.comparison_select_button.isEnabled()

    window.comparison_select_button.click()
    qapp.processEvents()

    comparison = window._comparison_state.comparison
    text = window.comparison_browser.toPlainText()
    assert window.baseline_name_label.text() == "基线：baseline-report.json"
    assert window.comparison_clear_button.isEnabled()
    assert "差值（当前 - 基线）" in text
    assert (
        f"技术分：基线 {comparison.baseline.technical_score} | "
        f"当前 {comparison.current.technical_score} | "
        f"差值 {comparison.technical_score_delta:+d}"
    ) in text
    assert (
        f"审阅分：基线 {comparison.baseline.reviewed_score} | "
        f"当前 {comparison.current.reviewed_score} | "
        f"差值 {comparison.reviewed_score_delta:+d}"
    ) in text
    assert "覆盖率：基线 100.0% | 当前 75.0% | 差值 -25.0%" in text
    assert "覆盖状态：基线 已完成 | 当前 覆盖受限" in text
    assert "发现数：基线 1 | 当前 2 | 差值 +1" in text
    assert text.index("ALPHA_RULE: 基线 0 | 当前 1 | 差值 +1") < text.index(
        "BASELINE_RULE: 基线 1 | 当前 0 | 差值 -1"
    )
    assert text.index("BASELINE_RULE: 基线 1 | 当前 0 | 差值 -1") < text.index(
        "ZETA_RULE: 基线 0 | 当前 1 | 差值 +1"
    )
    assert "新增限制：文件扫描受限" in text
    assert "已解除限制：无" in text
    assert all(
        claim not in text
        for claim in ("新增发现", "已修复发现", "匹配发现", "未变化发现")
    )
    window.close()


def test_report_page_comparison_selection_requires_parseable_current_report(qapp) -> None:
    window = create_window()
    current = _audit_outcome((_disposition_finding(11),))
    window._scan_completed(
        app_module.AuditOutcome(
            findings=current.findings,
            score=current.score,
            reviewed_score=current.reviewed_score,
            evaluated_at=current.evaluated_at,
            rule_version=current.rule_version,
            report_json='{"invalid":"current"}',
            report_html=current.report_html,
            scanned_roots=current.scanned_roots,
        )
    )

    assert not window.comparison_select_button.isEnabled()
    window.close()


def test_comparison_category_rows_show_baseline_current_and_signed_delta() -> None:
    baseline = ReportSummary(
        schema_version=2,
        supported_use_boundary="personal_non_regulated_configuration",
        supported_use_boundary_verified=True,
        technical_score=80,
        reviewed_score=82,
        coverage=1.0,
        coverage_state=app_module.CoverageState.COMPLETE,
        finding_count=9,
        rule_counts=(("ALPHA", 2), ("BETA", 3), ("SAME", 4)),
        severity_counts=(("high", 2), ("low", 3), ("medium", 4)),
        disposition_counts=(
            ("accepted_risk", 2),
            ("false_positive", 3),
            ("open", 4),
        ),
        limits=(),
    )
    current = ReportSummary(
        schema_version=2,
        supported_use_boundary="personal_non_regulated_configuration",
        supported_use_boundary_verified=True,
        technical_score=70,
        reviewed_score=76,
        coverage=1.0,
        coverage_state=app_module.CoverageState.COMPLETE,
        finding_count=16,
        rule_counts=(("BETA", 5), ("GAMMA", 7), ("SAME", 4)),
        severity_counts=(("critical", 7), ("high", 5), ("medium", 4)),
        disposition_counts=(
            ("accepted_risk", 2),
            ("expired", 7),
            ("open", 7),
        ),
        limits=(),
    )

    text = app_module._comparison_text(
        compare_report_summaries(baseline, current)
    )

    assert "历史基线未声明 Personal 边界" not in text

    rule_rows = (
        "ALPHA: 基线 2 | 当前 0 | 差值 -2",
        "BETA: 基线 3 | 当前 5 | 差值 +2",
        "GAMMA: 基线 0 | 当前 7 | 差值 +7",
        "SAME: 基线 4 | 当前 4 | 差值 +0",
    )
    severity_rows = (
        "严重: 基线 0 | 当前 7 | 差值 +7",
        "高: 基线 2 | 当前 5 | 差值 +3",
        "低: 基线 3 | 当前 0 | 差值 -3",
        "中: 基线 4 | 当前 4 | 差值 +0",
    )
    disposition_rows = (
        "已接受风险: 基线 2 | 当前 2 | 差值 +0",
        "已过期: 基线 0 | 当前 7 | 差值 +7",
        "误报: 基线 3 | 当前 0 | 差值 -3",
        "待处理: 基线 4 | 当前 7 | 差值 +3",
    )
    for rows in (rule_rows, severity_rows, disposition_rows):
        assert all(row in text for row in rows)
        assert [text.index(row) for row in rows] == sorted(
            text.index(row) for row in rows
        )


def test_comparison_text_marks_legacy_baseline_boundary_unverified() -> None:
    baseline = ReportSummary(
        schema_version=1,
        supported_use_boundary=None,
        supported_use_boundary_verified=False,
        technical_score=100,
        reviewed_score=100,
        coverage=1.0,
        coverage_state=app_module.CoverageState.COMPLETE,
        finding_count=0,
        rule_counts=(),
        severity_counts=(),
        disposition_counts=(),
        limits=(),
    )
    current = ReportSummary(
        schema_version=2,
        supported_use_boundary="personal_non_regulated_configuration",
        supported_use_boundary_verified=True,
        technical_score=100,
        reviewed_score=100,
        coverage=1.0,
        coverage_state=app_module.CoverageState.COMPLETE,
        finding_count=0,
        rule_counts=(),
        severity_counts=(),
        disposition_counts=(),
        limits=(),
    )

    text = app_module._comparison_text(
        compare_report_summaries(baseline, current)
    )

    assert "历史基线未声明 Personal 边界；仅比较聚合数据。" in text


def test_comparison_valid_secret_bearing_baseline_retains_only_aggregates(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker = "baseline-private-marker"
    baseline_finding = Finding(
        "PRIVATE_RULE",
        RiskDomain.CREDENTIALS,
        Severity.HIGH,
        "a" * 64,
        (Evidence(f"{marker}.env", "b" * 64, f"masked-{marker}"),),
        "c" * 64,
    )
    baseline_record = DispositionRecord(
        baseline_finding.disposition_ref,
        baseline_finding.rule_id,
        DispositionStatus.FALSE_POSITIVE,
        f"reason-{marker}",
        f"reviewer-{marker}",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )
    baseline = _audit_outcome((baseline_finding,), (baseline_record,))
    baseline_path = tmp_path / "private-baseline.json"
    baseline_path.write_text(baseline.report_json, encoding="utf-8")
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *args, **kwargs: (str(baseline_path), "JSON (*.json)"),
    )
    original_protected = []
    monkeypatch.setattr(
        app_module,
        "save_protected_state",
        lambda snapshot: original_protected.append(snapshot),
    )
    window = create_window()
    current = _audit_outcome((_disposition_finding(21),))
    window._scan_completed(current)

    window.comparison_select_button.click()
    qapp.processEvents()

    comparison_surfaces = " ".join(
        (
            repr(window._comparison_state),
            window.baseline_name_label.text(),
            window.baseline_name_label.toolTip(),
            window.baseline_name_label.accessibleName(),
            window.baseline_name_label.accessibleDescription(),
            window.comparison_browser.toPlainText(),
            window.comparison_browser.toolTip(),
            window.comparison_browser.accessibleName(),
            window.comparison_browser.accessibleDescription(),
        )
    )
    assert marker not in comparison_surfaces
    assert str(baseline_path) not in comparison_surfaces
    assert baseline.report_json not in repr(window.__dict__)
    assert baseline_finding.root_fingerprint not in comparison_surfaces
    assert baseline_finding.evidence[0].fingerprint not in comparison_surfaces
    assert baseline_finding.disposition_ref not in comparison_surfaces
    assert "reason-" not in comparison_surfaces
    assert "reviewer-" not in comparison_surfaces
    assert "2026-08-02T08:00:00Z" not in comparison_surfaces
    assert window.report_json == current.report_json
    assert window.report_html == current.report_html
    assert original_protected == []
    window.close()


@pytest.mark.parametrize("kind", ("invalid", "oversized"))
def test_comparison_invalid_baseline_uses_one_fixed_error_and_preserves_current(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    marker = "hostile-baseline-content-marker"
    baseline_path = tmp_path / f"{kind}.json"
    content = f'{{"private":"{marker}"}}'
    if kind == "oversized":
        content = marker + ("x" * (2 * 1024 * 1024))
    baseline_path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *args, **kwargs: (str(baseline_path), "JSON (*.json)"),
    )
    warnings = []
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *args: warnings.append(args[1:]),
    )
    window = create_window()
    current = _audit_outcome((_disposition_finding(31),))
    window._scan_completed(current)
    original = (
        window._audit_outcome,
        window.report_json,
        window.report_html,
        window._report_roots,
        window._dispositions,
        window._protected_state_invalid,
    )

    window.comparison_select_button.click()
    qapp.processEvents()

    assert window._comparison_state is None
    assert window.baseline_name_label.text() == "基线：未选择"
    assert not window.comparison_clear_button.isEnabled()
    assert warnings == [("基线报告错误", "无法读取基线报告。")]
    assert marker not in repr(warnings)
    assert str(baseline_path) not in repr(warnings)
    assert (
        window._audit_outcome,
        window.report_json,
        window.report_html,
        window._report_roots,
        window._dispositions,
        window._protected_state_invalid,
    ) == original
    window.close()


@pytest.mark.parametrize(
    "target",
    ("dialog", "load_report_summary", "parse_report_summary", "compare_report_summaries"),
)
def test_comparison_callback_contains_unexpected_errors_without_private_text(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target: str,
) -> None:
    marker = f"private-{target}-marker"
    baseline_path = tmp_path / "valid-baseline.json"
    baseline_path.write_text(
        _audit_outcome((_disposition_finding(41),)).report_json,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *args, **kwargs: (str(baseline_path), "JSON (*.json)"),
    )
    if target == "dialog":
        monkeypatch.setattr(
            QFileDialog,
            "getOpenFileName",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(marker)),
        )
    else:
        monkeypatch.setattr(
            app_module,
            target,
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(marker)),
        )
    warnings = []
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *args: warnings.append(args[1:]),
    )
    window = create_window()
    current = _audit_outcome((_disposition_finding(42),))
    window._scan_completed(current)

    window._select_baseline_report()

    assert window._comparison_state is None
    assert warnings == [("基线报告错误", "无法读取基线报告。")]
    assert marker not in repr(warnings)
    assert window.report_json == current.report_json
    assert window._audit_outcome is current
    window.close()


def test_comparison_filter_refresh_clear_and_export_isolation(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    finding = _disposition_finding(51)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(_audit_outcome((finding,)).report_json, encoding="utf-8")
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *args, **kwargs: (str(baseline_path), "JSON (*.json)"),
    )
    exports = []
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *args, **kwargs: ("comparison-export.json", "JSON (*.json)"),
    )
    monkeypatch.setattr(
        app_module,
        "export_new_report",
        lambda path, content, roots: exports.append((path, content, roots)),
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    monkeypatch.setattr(app_module, "save_protected_state", lambda snapshot: None)
    window = create_window()
    current = _audit_outcome((finding,))
    window._scan_completed(current)
    window.report_mode_combo.setCurrentText("JSON")
    window._export_report()
    window._select_baseline_report()
    first_state = window._comparison_state

    window.severity_filter_combo.setCurrentIndex(
        window.severity_filter_combo.findData(Severity.HIGH)
    )
    qapp.processEvents()
    assert window._comparison_state is first_state

    window._export_report()
    window.comparison_clear_button.click()
    window._export_report()
    assert window._comparison_state is None
    assert window.baseline_name_label.text() == "基线：未选择"
    assert exports[0] == exports[1] == exports[2]
    assert exports[0][1] == current.report_json
    assert exports[0][2] == current.scanned_roots

    window._select_baseline_report()
    first_state = window._comparison_state
    replacement = _disposition(finding, DispositionStatus.FALSE_POSITIVE)
    window._save_and_commit_dispositions((replacement,), EVALUATED_AT)
    assert window._comparison_state is not None
    assert window._comparison_state is not first_state
    assert (
        window._comparison_state.comparison.current.reviewed_score
        == window._audit_outcome.reviewed_score.total
    )
    window.close()


@pytest.mark.parametrize("reset", ("invalidate", "scan_failure", "scan_start", "root_change"))
def test_comparison_scan_lifecycle_resets_transient_state(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reset: str,
) -> None:
    root = tmp_path / "current-root"
    next_root = tmp_path / "next-root"
    root.mkdir()
    next_root.mkdir()
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        _audit_outcome((_disposition_finding(61),)).report_json,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *args, **kwargs: (str(baseline_path), "JSON (*.json)"),
    )
    window = create_window()
    window._scan_completed(_audit_outcome((_disposition_finding(62),)))
    window._select_baseline_report()
    assert window._comparison_state is not None

    if reset == "invalidate":
        window._invalidate_report()
    elif reset == "scan_failure":
        window._scan_failed("scan_failed")
    elif reset == "root_change":
        monkeypatch.setattr(
            QFileDialog,
            "getExistingDirectory",
            lambda *args, **kwargs: str(next_root),
        )
        window._select_folder()
    else:
        window._roots = (root,)
        window._scope_preview = app_module._scope_preview_for((root,))
        window.supported_data_checkbox.setChecked(True)
        window.scope_consent_checkbox.setEnabled(True)
        window.scope_consent_checkbox.setChecked(True)
        monkeypatch.setattr(
            app_module,
            "AuditWorker",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("private")),
        )
        window._start_scan()

    assert window._comparison_state is None
    assert window.baseline_name_label.text() == "基线：未选择"
    assert not window.comparison_clear_button.isEnabled()
    assert "baseline.json" not in window.comparison_browser.toPlainText()
    window.close()


@pytest.mark.parametrize(
    ("surface", "reset"),
    (
        ("baseline_label", "clear"),
        ("comparison_browser", "root_change"),
        ("clear_command", "invalidate"),
        ("select_command", "scan_failure"),
    ),
)
def test_comparison_reset_attempts_each_surface_after_qt_setter_failure(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    surface: str,
    reset: str,
) -> None:
    baseline_path = tmp_path / "stale-baseline.json"
    baseline_path.write_text(
        _audit_outcome((_disposition_finding(81),)).report_json,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *args, **kwargs: (str(baseline_path), "JSON (*.json)"),
    )
    window = create_window()
    current = _audit_outcome((_disposition_finding(82),))
    window._scan_completed(current)
    window._select_baseline_report()
    assert window._comparison_state is not None
    original_current = (
        window._audit_outcome,
        window.report_json,
        window.report_html,
        window._report_roots,
    )

    target = {
        "baseline_label": window.baseline_name_label,
        "comparison_browser": window.comparison_browser,
        "clear_command": window.comparison_clear_button,
        "select_command": window.comparison_select_button,
    }[surface]
    setter_name = {
        "baseline_label": "setText",
        "comparison_browser": "setPlainText",
        "clear_command": "setEnabled",
        "select_command": "setEnabled",
    }[surface]
    monkeypatch.setattr(
        target,
        setter_name,
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError(f"private-{surface}-marker")
        ),
    )

    if reset == "clear":
        window._clear_comparison_callback()
    elif reset == "root_change":
        next_root = tmp_path / "next-root"
        next_root.mkdir()
        monkeypatch.setattr(
            QFileDialog,
            "getExistingDirectory",
            lambda *args, **kwargs: str(next_root),
        )
        window._select_folder()
    elif reset == "invalidate":
        window._invalidate_report()
    else:
        window._scan_failed("scan_failed")

    assert window._comparison_state is None
    if surface != "baseline_label":
        assert window.baseline_name_label.text() == "基线：未选择"
    if surface != "comparison_browser":
        assert window.comparison_browser.toPlainText() == "尚未选择基线报告。"
    if surface != "clear_command":
        assert not window.comparison_clear_button.isEnabled()
    if surface != "select_command":
        assert window.comparison_select_button.isEnabled() is (reset == "clear")
    if reset == "clear":
        assert (
            window._audit_outcome,
            window.report_json,
            window.report_html,
            window._report_roots,
        ) == original_current
    window.close()


def test_report_page_comparison_controls_fit_at_minimum_size(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        _audit_outcome((_disposition_finding(71),)).report_json,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *args, **kwargs: (str(baseline_path), "JSON (*.json)"),
    )
    window = create_window()
    window._scan_completed(_audit_outcome((_disposition_finding(72),)))
    window._select_baseline_report()
    window._switch_view(2)
    window.resize(960, 640)
    window.show()
    qapp.processEvents()

    comparison_controls = (
        window.comparison_select_button,
        window.comparison_clear_button,
        window.baseline_name_label,
    )
    assert all(control.isVisible() for control in comparison_controls)
    assert window.comparison_browser.isVisible()
    assert window.comparison_browser.frameShape() == QFrame.Shape.NoFrame
    assert not window.comparison_select_button.icon().isNull()
    assert not window.comparison_clear_button.icon().isNull()
    assert window.comparison_select_button.toolTip()
    assert window.comparison_clear_button.toolTip()
    for left, right in zip(comparison_controls, comparison_controls[1:]):
        assert not _global_rect(left).intersects(_global_rect(right))
    for control in comparison_controls:
        assert not _global_rect(control).intersects(_global_rect(window.report_browser))
        assert not _global_rect(control).intersects(
            _global_rect(window.comparison_browser)
        )
    assert not _global_rect(window.report_browser).intersects(
        _global_rect(window.comparison_browser)
    )
    window.close()


def test_report_page_elides_long_baseline_name_and_keeps_basename_tooltip(
    qapp,
) -> None:
    basename = "a" * 240 + ".json"
    current = _audit_outcome((_disposition_finding(73),))
    summary = app_module.parse_report_summary(current.report_json)
    state = app_module._ComparisonState(
        basename,
        compare_report_summaries(summary, summary),
    )
    window = create_window()
    window._scan_completed(current)
    window._switch_view(2)
    window.resize(1600, 640)
    window.show()
    qapp.processEvents()

    window._render_comparison(state)
    qapp.processEvents()
    wide_text = window.baseline_name_label.text()

    window.resize(960, 640)
    qapp.processEvents()
    narrow_text = window.baseline_name_label.text()
    label = window.baseline_name_label
    assert narrow_text != f"基线：{basename}"
    assert narrow_text.endswith("…")
    assert len(narrow_text) < len(wide_text)
    assert label.fontMetrics().horizontalAdvance(narrow_text) <= label.contentsRect().width()
    assert label.toolTip() == basename
    assert "/" not in label.toolTip()
    assert "\\" not in label.toolTip()

    window._clear_comparison_callback()
    assert label.text() == "基线：未选择"
    assert label.toolTip() == ""
    window.close()


def test_audit_scan_and_report_collection_budgets_are_shared() -> None:
    assert app_module.MAX_AUDIT_FINDINGS == MAX_REPORT_FINDINGS
    assert app_module.MAX_AUDIT_EVIDENCE == MAX_REPORT_EVIDENCE


def test_finding_disposition_controls_are_stable_private_and_selection_driven(qapp):
    finding = _disposition_finding()
    outcome = _audit_outcome((finding,))
    private_values = (
        finding.disposition_ref,
        DISPOSITION_KEY.hex(),
        r"C:\private\audit-root",
        "synthetic-raw-secret-marker",
    )
    window = create_window()
    window.resize(window.minimumSize())
    window._scan_completed(outcome)
    window._switch_view(1)
    window.show()
    qapp.processEvents()

    assert window.findings_table.columnCount() == 5
    assert [
        window.findings_table.horizontalHeaderItem(index).text()
        for index in range(5)
    ] == ["严重性", "规则", "来源", "已掩码证据", "处置状态"]
    assert window.findings_table.item(0, 4).text() == "待处理"
    assert not window.false_positive_button.isEnabled()
    assert not window.accepted_risk_button.isEnabled()
    assert not window.withdraw_button.isEnabled()
    for button in (
        window.false_positive_button,
        window.accepted_risk_button,
        window.withdraw_button,
    ):
        assert not button.icon().isNull()
        assert button.toolTip()
    assert (
        window.false_positive_button.text(),
        window.accepted_risk_button.text(),
        window.withdraw_button.text(),
    ) == ("标记误报", "接受风险", "撤销处置")
    assert (
        window.false_positive_button.toolTip(),
        window.accepted_risk_button.toolTip(),
        window.withdraw_button.toolTip(),
    ) == (
        "创建或替换误报处置",
        "创建或替换接受风险处置",
        "撤销此风险发现的处置",
    )

    window.findings_table.selectRow(0)
    qapp.processEvents()

    assert window.false_positive_button.isEnabled()
    assert window.accepted_risk_button.isEnabled()
    assert not window.withdraw_button.isEnabled()
    actions = (
        window.false_positive_button,
        window.accepted_risk_button,
        window.withdraw_button,
    )
    for left, right in zip(actions, actions[1:]):
        assert not _global_rect(left).intersects(_global_rect(right))
    assert not _global_rect(actions[0]).intersects(_global_rect(window.findings_table))
    status_item = window.findings_table.item(0, 4)
    assert (
        window.findings_table.fontMetrics().horizontalAdvance(status_item.text())
        < window.findings_table.columnWidth(4)
    )
    visible = " ".join(
        window.findings_table.item(0, column).text()
        for column in range(window.findings_table.columnCount())
    )
    combined = " ".join(
        (visible, *(button.toolTip() for button in actions), repr(outcome))
    )
    assert all(value not in combined for value in private_values)

    window._dispositions = (
        _disposition(finding, DispositionStatus.FALSE_POSITIVE),
    )
    window._refresh_disposition_ui(EVALUATED_AT)
    assert window.findings_table.item(0, 4).text() == "误报"
    assert window.withdraw_button.isEnabled()

    window.findings_table.clearSelection()
    qapp.processEvents()
    assert not window.false_positive_button.isEnabled()
    assert not window.accepted_risk_button.isEnabled()
    assert not window.withdraw_button.isEnabled()
    window.close()


def test_filter_controls_use_canonical_data_count_findings_and_fit(qapp) -> None:
    finding = Finding(
        rule_id="GENERIC_API_KEY",
        domain=RiskDomain.CREDENTIALS,
        severity=Severity.HIGH,
        root_fingerprint="1" * 64,
        evidence=(
            Evidence("first.env", "2" * 64, "masked-one"),
            Evidence("second.env", "3" * 64, "masked-two"),
        ),
        disposition_ref="4" * 64,
    )
    window = create_window()
    window._scan_completed(_audit_outcome((finding,)))
    window._switch_view(1)
    window.resize(960, 640)
    window.show()
    qapp.processEvents()

    assert [
        window.severity_filter_combo.itemData(index)
        for index in range(window.severity_filter_combo.count())
    ] == [None, *(severity.value for severity in Severity)]
    assert [
        window.domain_filter_combo.itemData(index)
        for index in range(window.domain_filter_combo.count())
    ] == [None, *(domain.value for domain in RiskDomain)]
    assert [
        window.disposition_filter_combo.itemData(index)
        for index in range(window.disposition_filter_combo.count())
    ] == [None, "open", "false_positive", "accepted_risk", "expired"]
    assert all(
        type(window.severity_filter_combo.itemData(index)) is str
        for index in range(1, window.severity_filter_combo.count())
    )
    assert all(
        type(window.domain_filter_combo.itemData(index)) is str
        for index in range(1, window.domain_filter_combo.count())
    )
    assert window.findings_count_label.text() == "显示 1 / 共 1 项发现"
    assert window.findings_table.rowCount() == 2

    controls = (
        window.severity_filter_combo,
        window.domain_filter_combo,
        window.disposition_filter_combo,
        window.findings_count_label,
    )
    original_sizes = tuple(control.size() for control in controls)
    for combo in controls[:3]:
        combo.setCurrentIndex(combo.count() - 1)
        qapp.processEvents()
    assert tuple(control.size() for control in controls) == original_sizes
    for left, right in zip(controls, controls[1:]):
        assert not _global_rect(left).intersects(_global_rect(right))
    for control in controls:
        assert not _global_rect(control).intersects(_global_rect(window.findings_table))
        assert not _global_rect(control).intersects(_global_rect(window.guidance_browser))
    for button in (
        window.false_positive_button,
        window.accepted_risk_button,
        window.withdraw_button,
    ):
        assert not _global_rect(button).intersects(_global_rect(window.findings_table))
        assert not _global_rect(button).intersects(_global_rect(window.guidance_browser))

    visible_controls = " ".join(
        combo.itemText(index)
        for combo in controls[:3]
        for index in range(combo.count())
    )
    assert all(
        value not in visible_controls
        for value in (
            finding.disposition_ref,
            "Synthetic audit review",
            "Local reviewer",
            "synthetic-raw-match-marker",
            r"C:\private\audit-root",
        )
    )
    window.close()


def _same_row_filter_findings() -> tuple[Finding, Finding]:
    return (
        Finding(
            rule_id="RULE_HIGH",
            domain=RiskDomain.CREDENTIALS,
            severity=Severity.HIGH,
            root_fingerprint="1" * 64,
            evidence=(Evidence("high.env", "2" * 64, "masked-high"),),
            disposition_ref="3" * 64,
        ),
        Finding(
            rule_id="RULE_LOW",
            domain=RiskDomain.RETENTION,
            severity=Severity.LOW,
            root_fingerprint="4" * 64,
            evidence=(Evidence("low.env", "5" * 64, "masked-low"),),
            disposition_ref="6" * 64,
        ),
    )


def test_filter_same_row_count_clears_stale_selection_before_repopulation(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = _same_row_filter_findings()
    window = create_window()
    window._scan_completed(_audit_outcome((first, second)))
    window.severity_filter_combo.setCurrentIndex(
        window.severity_filter_combo.findData(Severity.HIGH)
    )
    window.findings_table.selectRow(0)
    qapp.processEvents()
    actions = (
        window.false_positive_button,
        window.accepted_risk_button,
        window.withdraw_button,
    )
    assert window._row_findings == [first]
    assert window._selected_finding() is first
    assert window.findings_table.currentRow() == 0
    assert window.false_positive_button.isEnabled()
    assert window.accepted_risk_button.isEnabled()

    enabled_during_switch = []
    original_set_enabled = QPushButton.setEnabled

    def track_action_enable(button, enabled):
        if button in actions and enabled:
            enabled_during_switch.append(button)
        return original_set_enabled(button, enabled)

    monkeypatch.setattr(QPushButton, "setEnabled", track_action_enable)

    window.severity_filter_combo.setCurrentIndex(
        window.severity_filter_combo.findData(Severity.LOW)
    )
    qapp.processEvents()

    assert window._row_findings == [second]
    assert window.findings_table.rowCount() == 1
    assert window.findings_table.currentRow() == -1
    assert not window.findings_table.selectionModel().hasSelection()
    assert window.guidance_browser.toPlainText() == "选择一项风险以查看人工步骤。"
    assert all(not button.isEnabled() for button in actions)
    assert enabled_during_switch == []

    window.findings_table.selectRow(0)
    qapp.processEvents()

    assert window._selected_finding() is second
    assert window.findings_table.currentRow() == 0
    assert window.false_positive_button.isEnabled()
    assert window.accepted_risk_button.isEnabled()
    window.close()


def test_filter_disposition_expiry_refresh_restores_selection_only_by_identity(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = _same_row_filter_findings()
    active_first = _disposition(
        first,
        DispositionStatus.FALSE_POSITIVE,
        expires_at="2026-08-02T12:00:02Z",
    )
    expired_second = _disposition(
        second,
        DispositionStatus.FALSE_POSITIVE,
        expires_at="2026-08-02T11:59:59Z",
    )
    clock = [EVALUATED_AT]
    monkeypatch.setattr(app_module, "_utc_now", lambda: clock[0])
    window = create_window()
    window._dispositions = (active_first, expired_second)
    window._scan_completed(
        _audit_outcome((first, second), (active_first, expired_second))
    )
    window.disposition_filter_combo.setCurrentIndex(
        window.disposition_filter_combo.findData("expired")
    )
    window.findings_table.selectRow(0)
    qapp.processEvents()
    assert window._row_findings == [second]
    assert window._selected_finding() is second

    clock[0] = EVALUATED_AT + timedelta(seconds=2)
    window._handle_expiry_timeout()
    qapp.processEvents()

    assert window._row_findings == [first, second]
    assert window.findings_table.currentRow() == 1
    assert window._selected_finding() is second
    window.close()

    replacement = create_window()
    replacement._dispositions = (active_first,)
    replacement._scan_completed(_audit_outcome((first, second), (active_first,)))
    replacement.disposition_filter_combo.setCurrentIndex(
        replacement.disposition_filter_combo.findData("false_positive")
    )
    replacement.findings_table.selectRow(0)
    qapp.processEvents()
    assert replacement._row_findings == [first]
    assert replacement._selected_finding() is first

    active_second = _disposition(second, DispositionStatus.FALSE_POSITIVE)
    selected_row = replacement.findings_table.currentRow()
    refreshed = replacement._reviewed_outcome((active_second,), EVALUATED_AT)
    replacement._dispositions = (active_second,)
    replacement._audit_outcome = refreshed
    replacement.report_json = refreshed.report_json
    replacement.report_html = refreshed.report_html
    replacement._refresh_reviewed_ui_no_throw(
        refreshed.evaluated_at,
        selected_row,
        failure_message="处置已保存，界面刷新受限。",
    )
    qapp.processEvents()

    assert replacement._row_findings == [second]
    assert replacement.findings_table.rowCount() == 1
    assert replacement.findings_table.currentRow() == -1
    assert not replacement.findings_table.selectionModel().hasSelection()
    assert replacement.guidance_browser.toPlainText() == (
        "选择一项风险以查看人工步骤。"
    )
    assert not replacement.false_positive_button.isEnabled()
    assert not replacement.accepted_risk_button.isEnabled()
    assert not replacement.withdraw_button.isEnabled()
    replacement.close()


def test_filter_isolation_changes_only_visible_rows_and_selection(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = (
        Finding(
            "RULE_CRITICAL",
            RiskDomain.EXPOSURE,
            Severity.CRITICAL,
            "1" * 64,
            (
                Evidence("critical-1.env", "2" * 64, "masked-one"),
                Evidence("critical-2.env", "3" * 64, "masked-two"),
            ),
            "4" * 64,
        ),
        Finding(
            "RULE_HIGH",
            RiskDomain.CREDENTIALS,
            Severity.HIGH,
            "5" * 64,
            (Evidence("high.env", "6" * 64, "masked-high"),),
            "7" * 64,
        ),
        Finding(
            "RULE_MEDIUM",
            RiskDomain.PRIVACY,
            Severity.MEDIUM,
            "8" * 64,
            (Evidence("medium.env", "9" * 64, "masked-medium"),),
            "a" * 64,
        ),
        Finding(
            "RULE_LOW",
            RiskDomain.RETENTION,
            Severity.LOW,
            "b" * 64,
            (Evidence("low.env", "c" * 64, "masked-low"),),
            "d" * 64,
        ),
    )
    records = (
        _disposition(findings[1], DispositionStatus.FALSE_POSITIVE),
        _disposition(findings[2], DispositionStatus.ACCEPTED_RISK),
        _disposition(
            findings[3],
            DispositionStatus.FALSE_POSITIVE,
            expires_at="2026-08-02T11:59:59Z",
        ),
    )
    saved = []
    exports = []
    monkeypatch.setattr(app_module, "save_protected_state", saved.append)
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *args, **kwargs: ("filtered-export.json", "JSON (*.json)"),
    )
    monkeypatch.setattr(
        app_module,
        "export_new_report",
        lambda path, content, roots: exports.append((path, content, roots)),
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    window = create_window()
    window._dispositions = records
    outcome = _audit_outcome(findings, records)
    window._scan_completed(outcome)
    window.report_mode_combo.setCurrentText("JSON")
    window.save_button.click()
    original = (
        window._audit_outcome,
        window._audit_outcome.findings,
        window._audit_outcome.score,
        window._audit_outcome.reviewed_score,
        window.report_json,
        window.report_html,
        window._dispositions,
        window._protected_state_invalid,
        window._report_roots,
        window.report_browser.toPlainText(),
        window._expiry_timer.isActive(),
        window._expiry_timer.interval(),
    )

    window.disposition_filter_combo.setCurrentIndex(
        window.disposition_filter_combo.findData("false_positive")
    )
    qapp.processEvents()
    assert window.findings_count_label.text() == "显示 1 / 共 4 项发现"
    assert window.findings_table.rowCount() == 1
    assert window._row_findings == [findings[1]]
    window.findings_table.selectRow(0)
    assert window.false_positive_button.isEnabled()

    window.severity_filter_combo.setCurrentIndex(
        window.severity_filter_combo.findData(Severity.CRITICAL)
    )
    qapp.processEvents()
    assert window.findings_count_label.text() == "显示 0 / 共 4 项发现"
    assert window.findings_table.rowCount() == 0
    assert window.findings_table.currentRow() == -1
    assert window.guidance_browser.toPlainText() == "当前筛选条件下无匹配风险发现。"
    assert "审计未发现风险" not in window.guidance_browser.toPlainText()
    assert not window.false_positive_button.isEnabled()
    assert not window.accepted_risk_button.isEnabled()
    assert not window.withdraw_button.isEnabled()
    window._review_guidance()
    qapp.processEvents()
    assert window.guidance_browser.toPlainText() == "当前筛选条件下无匹配风险发现。"

    window.disposition_filter_combo.setCurrentIndex(0)
    qapp.processEvents()
    assert window.findings_count_label.text() == "显示 1 / 共 4 项发现"
    assert window.findings_table.rowCount() == 2
    assert window._row_findings == [findings[0], findings[0]]
    assert window.guidance_browser.toPlainText() == "选择一项风险以查看人工步骤。"

    window.severity_filter_combo.setCurrentIndex(0)
    window.domain_filter_combo.setCurrentIndex(
        window.domain_filter_combo.findData(RiskDomain.PRIVACY)
    )
    qapp.processEvents()
    assert window._row_findings == [findings[2]]
    assert window.findings_count_label.text() == "显示 1 / 共 4 项发现"
    window.save_button.click()

    assert (
        window._audit_outcome,
        window._audit_outcome.findings,
        window._audit_outcome.score,
        window._audit_outcome.reviewed_score,
        window.report_json,
        window.report_html,
        window._dispositions,
        window._protected_state_invalid,
        window._report_roots,
        window.report_browser.toPlainText(),
        window._expiry_timer.isActive(),
        window._expiry_timer.interval(),
    ) == original
    assert window.report_json == outcome.report_json
    assert window.report_html == outcome.report_html
    assert len(exports) == 2
    assert exports[0] == exports[1]
    assert exports[0][1] == outcome.report_json
    assert exports[0][2] == outcome.scanned_roots
    assert saved == []
    window.close()


def test_filter_isolation_contains_unexpected_callback_error(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _disposition_finding()
    window = create_window()
    window._scan_completed(_audit_outcome((finding,)))
    original = (
        window._audit_outcome,
        window.report_json,
        window.report_html,
        window._dispositions,
        window._protected_state_invalid,
        window._report_roots,
    )
    marker = "private-filter-callback-marker"
    saves = []
    monkeypatch.setattr(app_module, "save_protected_state", saves.append)
    monkeypatch.setattr(
        app_module,
        "filter_findings",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(marker)),
    )

    window.severity_filter_combo.setCurrentIndex(
        window.severity_filter_combo.findData(Severity.HIGH)
    )
    qapp.processEvents()

    assert window.findings_table.rowCount() == 0
    assert window._row_findings == []
    assert window.findings_count_label.text() == "无法筛选风险发现，请重试。"
    assert window.guidance_browser.toPlainText() == "无法筛选风险发现，请重试。"
    assert window.findings_table.currentRow() == -1
    window.resize(960, 640)
    window.show()
    qapp.processEvents()
    assert window.findings_count_label.sizeHint().width() <= window.findings_count_label.width()
    assert not window.false_positive_button.isEnabled()
    assert not window.accepted_risk_button.isEnabled()
    assert not window.withdraw_button.isEnabled()
    assert (
        window._audit_outcome,
        window.report_json,
        window.report_html,
        window._dispositions,
        window._protected_state_invalid,
        window._report_roots,
    ) == original
    assert marker not in " ".join(
        (
            window.findings_count_label.text(),
            window.guidance_browser.toPlainText(),
            window.status_label.text(),
            window.report_browser.toPlainText(),
        )
    )
    assert saves == []
    window.close()


def test_filter_disposition_create_replace_and_withdraw_refresh_visible_rows(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _disposition_finding()
    false_positive = _disposition(finding, DispositionStatus.FALSE_POSITIVE)
    accepted_risk = _disposition(finding, DispositionStatus.ACCEPTED_RISK)
    saved = []
    monkeypatch.setattr(app_module, "save_protected_state", saved.append)
    window = create_window()
    window._scan_completed(_audit_outcome((finding,)))
    window.disposition_filter_combo.setCurrentIndex(
        window.disposition_filter_combo.findData("open")
    )
    window.findings_table.selectRow(0)

    window._save_and_commit_dispositions((false_positive,), EVALUATED_AT)

    assert window.findings_count_label.text() == "显示 0 / 共 1 项发现"
    assert window.findings_table.rowCount() == 0
    assert window.guidance_browser.toPlainText() == "当前筛选条件下无匹配风险发现。"
    window.disposition_filter_combo.setCurrentIndex(
        window.disposition_filter_combo.findData("false_positive")
    )
    qapp.processEvents()
    assert window.findings_table.rowCount() == 1
    assert window.findings_table.item(0, 4).text() == "误报"

    window._save_and_commit_dispositions((accepted_risk,), EVALUATED_AT)

    assert window.findings_table.rowCount() == 0
    window.disposition_filter_combo.setCurrentIndex(
        window.disposition_filter_combo.findData("accepted_risk")
    )
    qapp.processEvents()
    assert window.findings_table.rowCount() == 1
    assert window.findings_table.item(0, 4).text() == "已接受风险"

    window._save_and_commit_dispositions((), EVALUATED_AT)

    assert window.findings_table.rowCount() == 0
    window.disposition_filter_combo.setCurrentIndex(
        window.disposition_filter_combo.findData("open")
    )
    qapp.processEvents()
    assert window.findings_table.rowCount() == 1
    assert window.findings_table.item(0, 4).text() == "待处理"
    assert window._dispositions == ()
    assert len(saved) == 3
    window.close()


def test_filter_disposition_refresh_contains_unexpected_filter_error_after_save(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _disposition_finding()
    candidate = (_disposition(finding, DispositionStatus.FALSE_POSITIVE),)
    marker = "private-saved-filter-marker"
    saved = []
    monkeypatch.setattr(app_module, "save_protected_state", saved.append)
    window = create_window()
    window._scan_completed(_audit_outcome((finding,)))
    window.findings_table.selectRow(0)
    monkeypatch.setattr(
        app_module,
        "filter_findings",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(marker)),
    )

    window._save_and_commit_dispositions(candidate, EVALUATED_AT)

    assert len(saved) == 1
    assert window._dispositions == candidate
    assert window._audit_outcome.reviewed_score.total == 100
    assert json.loads(window.report_json)["findings"][0]["disposition"][
        "status"
    ] == "false_positive"
    assert window.findings_table.rowCount() == 0
    assert window._row_findings == []
    assert window.findings_count_label.text() == "无法筛选风险发现，请重试。"
    assert window.guidance_browser.toPlainText() == "无法筛选风险发现，请重试。"
    assert marker not in " ".join(
        (
            window.findings_count_label.text(),
            window.guidance_browser.toPlainText(),
            window.status_label.text(),
            window.report_browser.toPlainText(),
        )
    )
    window.close()


def test_filter_scan_completion_invalidation_and_failure_refresh_view(qapp) -> None:
    high = _disposition_finding()
    low = Finding(
        "RULE_LOW",
        RiskDomain.RETENTION,
        Severity.LOW,
        "a" * 64,
        (Evidence("low.env", "b" * 64, "masked-low"),),
        "c" * 64,
    )
    window = create_window()
    window.severity_filter_combo.setCurrentIndex(
        window.severity_filter_combo.findData(Severity.HIGH)
    )

    window._scan_completed(_audit_outcome((high, low)))

    assert window.findings_count_label.text() == "显示 1 / 共 2 项发现"
    assert window._row_findings == [high]

    window._invalidate_report()

    assert window.findings_count_label.text() == "显示 0 / 共 0 项发现"
    assert window.findings_table.rowCount() == 0
    assert window._row_findings == []
    assert window.guidance_browser.toPlainText() == "选择一项风险以查看人工步骤。"

    window._scan_completed(_audit_outcome((high, low)))
    assert window.findings_count_label.text() == "显示 1 / 共 2 项发现"
    window._scan_failed("private-code")
    assert window.findings_count_label.text() == "显示 0 / 共 0 项发现"
    assert window.findings_table.rowCount() == 0
    assert window._row_findings == []
    assert window._audit_outcome is None
    window.close()


def test_filter_scan_completion_contains_unexpected_filter_error(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _disposition_finding()
    outcome = _audit_outcome((finding,))
    marker = "private-scan-filter-marker"
    monkeypatch.setattr(
        app_module,
        "filter_findings",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(marker)),
    )
    window = create_window()

    window._scan_completed(outcome)

    assert window._audit_outcome is outcome
    assert window.report_json == outcome.report_json
    assert window.report_html == outcome.report_html
    assert window.findings_table.rowCount() == 0
    assert window._row_findings == []
    assert window.findings_count_label.text() == "无法筛选风险发现，请重试。"
    assert window.guidance_browser.toPlainText() == "无法筛选风险发现，请重试。"
    assert marker not in " ".join(
        (
            window.findings_count_label.text(),
            window.guidance_browser.toPlainText(),
            window.status_label.text(),
            window.report_browser.toPlainText(),
        )
    )
    window.close()


@pytest.mark.parametrize(
    ("status", "expires_at", "expected"),
    (
        (None, None, "待处理"),
        (
            DispositionStatus.FALSE_POSITIVE,
            "2026-08-03T08:00:00Z",
            "误报",
        ),
        (
            DispositionStatus.ACCEPTED_RISK,
            "2026-08-03T08:00:00Z",
            "已接受风险",
        ),
        (
            DispositionStatus.FALSE_POSITIVE,
            "2026-08-02T11:00:00Z",
            "已过期",
        ),
    ),
)
def test_disposition_status_and_controls_fit_at_minimum_size(
    qapp,
    status: DispositionStatus | None,
    expires_at: str | None,
    expected: str,
) -> None:
    finding = _disposition_finding()
    records = (
        ()
        if status is None
        else (
            _disposition(
                finding,
                status,
                created_at="2026-08-01T08:00:00Z",
                expires_at=expires_at,
            ),
        )
    )
    window = create_window()
    window._dispositions = records
    window._scan_completed(_audit_outcome((finding,), records))
    window._switch_view(1)
    window.resize(960, 640)
    window.show()
    window.findings_table.selectRow(0)
    qapp.processEvents()

    assert window.findings_table.item(0, 4).text() == expected
    assert window.findings_table.horizontalHeader().sectionSizeHint(
        4
    ) <= window.findings_table.columnWidth(4)
    assert window.findings_table.sizeHintForColumn(
        4
    ) <= window.findings_table.columnWidth(4)
    actions = (
        window.false_positive_button,
        window.accepted_risk_button,
        window.withdraw_button,
    )
    for button in actions:
        assert button.sizeHint().width() <= button.width()
        assert button.sizeHint().height() <= button.height()
        assert not _global_rect(button).intersects(_global_rect(window.findings_table))
    for left, right in zip(actions, actions[1:]):
        assert not _global_rect(left).intersects(_global_rect(right))
    window.close()


def test_long_valid_finding_values_are_elided_without_hiding_disposition(qapp):
    rule_id = "R" * 64
    source = "s" * 80
    masked = "m" * 80
    finding = Finding(
        rule_id=rule_id,
        domain=RiskDomain.CREDENTIALS,
        severity=Severity.HIGH,
        root_fingerprint="1" * 64,
        evidence=(Evidence(source, "2" * 64, masked),),
        disposition_ref="3" * 64,
    )
    window = create_window()
    window._scan_completed(_audit_outcome((finding,)))
    window._switch_view(1)
    window.resize(960, 640)
    window.show()
    qapp.processEvents()

    viewport = window.findings_table.viewport()
    status_left = window.findings_table.columnViewportPosition(4)
    status_width = window.findings_table.columnWidth(4)
    assert window.findings_table.horizontalScrollBar().maximum() == 0
    assert status_left >= 0
    assert status_left + status_width <= viewport.width()
    assert window.findings_table.textElideMode() is Qt.TextElideMode.ElideRight
    assert window.findings_table.item(0, 1).toolTip() == rule_id
    assert window.findings_table.item(0, 2).toolTip() == source
    assert window.findings_table.item(0, 3).toolTip() == masked
    assert window.findings_table.item(0, 4).text() == "待处理"
    window.close()


def test_disposition_dialog_validates_form_and_converts_local_expiry_to_utc(qapp):
    dialog = app_module._DispositionDialog(
        None,
        DispositionStatus.FALSE_POSITIVE,
        EVALUATED_AT,
    )
    ok_button = dialog.button_box.button(QDialogButtonBox.StandardButton.Ok)
    cancel_button = dialog.button_box.button(QDialogButtonBox.StandardButton.Cancel)

    assert dialog.status_combo.count() == 2
    assert dialog.windowTitle() == "风险发现处置"
    assert dialog.status_combo.currentText() == "误报"
    layout = dialog.layout()
    assert layout.labelForField(dialog.status_combo).text() == "状态"
    assert layout.labelForField(dialog.reason_edit).text() == "原因"
    assert layout.labelForField(dialog.reviewer_edit).text() == "复核人"
    assert layout.labelForField(dialog.expiry_edit).text() == "本地到期时间"
    assert ok_button.text() == "确定"
    assert cancel_button.text() == "取消"
    assert not ok_button.isEnabled()

    dialog.reason_edit.setText("Synthetic review reason")
    dialog.reviewer_edit.setText("Local reviewer")
    dialog.expiry_edit.setDateTime(
        QDateTime.fromString(
            "2026-08-03T20:34:56+08:00",
            Qt.DateFormat.ISODate,
        )
    )
    qapp.processEvents()

    assert ok_button.isEnabled()
    assert dialog.values() == (
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic review reason",
        "Local reviewer",
        "2026-08-03T12:34:56Z",
    )

    dialog.status_combo.setCurrentText("接受风险")
    assert dialog.values()[0] is DispositionStatus.ACCEPTED_RISK
    dialog.reason_edit.setText(r"C:\private\secret.txt")
    qapp.processEvents()
    assert not ok_button.isEnabled()
    dialog.reason_edit.setText("Synthetic review reason")
    dialog.expiry_edit.setDateTime(
        QDateTime.fromString(
            "2027-08-04T12:00:01Z",
            Qt.DateFormat.ISODate,
        )
    )
    qapp.processEvents()
    assert not ok_button.isEnabled()
    dialog.close()


def test_disposition_dialog_unexpected_validation_error_keeps_ok_disabled(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dialog = app_module._DispositionDialog(
        None,
        DispositionStatus.FALSE_POSITIVE,
        EVALUATED_AT,
    )
    ok_button = dialog.button_box.button(QDialogButtonBox.StandardButton.Ok)
    ok_button.setEnabled(True)
    monkeypatch.setattr(
        dialog,
        "values",
        lambda: (_ for _ in ()).throw(RuntimeError("private-validation-marker")),
    )

    dialog._update_validity()

    assert not ok_button.isEnabled()
    dialog.close()


def test_disposition_dialog_default_uses_qt_timezone_calendar_arithmetic(qapp):
    zone = QTimeZone(b"America/New_York")
    opened_at = datetime(2026, 2, 28, 12, 0, tzinfo=timezone.utc)
    dialog = app_module._DispositionDialog(
        None,
        DispositionStatus.FALSE_POSITIVE,
        opened_at,
        time_zone=zone,
    )

    default_expiry = dialog.expiry_edit.dateTime()
    assert default_expiry.timeZone() == zone
    assert default_expiry.date() == QDate(2026, 3, 30)
    assert default_expiry.time() == QTime(7, 0)
    expected_utc = datetime(2026, 3, 30, 11, 0, tzinfo=timezone.utc)
    assert default_expiry.toUTC().toSecsSinceEpoch() == int(expected_utc.timestamp())
    dialog.close()


@pytest.mark.parametrize(
    ("resolution", "expected"),
    (
        (
            QDateTime.TransitionResolution.PreferBefore,
            "2026-11-01T05:30:00Z",
        ),
        (
            QDateTime.TransitionResolution.PreferAfter,
            "2026-11-01T06:30:00Z",
        ),
    ),
)
def test_disposition_dialog_converts_dst_gap_and_fold_to_utc(
    qapp,
    resolution: QDateTime.TransitionResolution,
    expected: str,
) -> None:
    zone = QTimeZone(b"America/New_York")
    dialog = app_module._DispositionDialog(
        None,
        DispositionStatus.FALSE_POSITIVE,
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        time_zone=zone,
    )
    dialog.reason_edit.setText("Synthetic review reason")
    dialog.reviewer_edit.setText("Local reviewer")
    gap = QDateTime(QDate(2026, 3, 8), QTime(2, 30), zone)
    dialog.expiry_edit.setDateTime(gap)
    assert dialog.values()[3] == "2026-03-08T07:30:00Z"

    fold = QDateTime(QDate(2026, 11, 1), QTime(1, 30), zone, resolution)
    dialog.expiry_edit.setDateTime(fold)
    assert dialog.values()[3] == expected
    dialog.close()


def test_disposition_dialog_accepts_exact_366_day_expiry_only(qapp):
    opened_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    dialog = app_module._DispositionDialog(
        None,
        DispositionStatus.FALSE_POSITIVE,
        opened_at,
        time_zone=QTimeZone.utc(),
    )
    dialog.reason_edit.setText("Synthetic review reason")
    dialog.reviewer_edit.setText("Local reviewer")
    exact = QDateTime.fromMSecsSinceEpoch(
        int((opened_at + timedelta(days=366)).timestamp() * 1000),
        QTimeZone.utc(),
    )
    dialog.expiry_edit.setDateTime(exact)
    assert dialog.values()[3] == "2027-01-02T00:00:00Z"

    dialog.expiry_edit.setDateTime(exact.addSecs(1))
    with pytest.raises(ValueError, match="DISPOSITION_INVALID"):
        dialog.values()
    dialog.close()


def test_disposition_dialog_cancel_has_zero_write_or_state_change(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _disposition_finding()
    saved = []

    class CancelDialog:
        def __init__(self, parent, status, now):
            self.status = status

        def exec(self):
            return QDialog.DialogCode.Rejected

    monkeypatch.setattr(app_module, "_DispositionDialog", CancelDialog)
    monkeypatch.setattr(app_module, "save_protected_state", saved.append)
    window = create_window()
    window._scan_completed(_audit_outcome((finding,)))
    window.findings_table.selectRow(0)
    before = _window_transaction_state(window)

    window.false_positive_button.click()

    assert saved == []
    assert _window_transaction_state(window) == before
    window.close()


def test_create_rejects_expiry_that_passes_dialog_but_expires_before_commit(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _disposition_finding()
    opened_at = EVALUATED_AT
    commit_at = EVALUATED_AT + timedelta(minutes=2)
    clock = iter((opened_at, commit_at))
    events = []
    saved = []
    warnings = []

    def current_time():
        value = next(clock)
        events.append(("clock", value))
        return value

    class AcceptDialog:
        def __init__(self, parent, status, now):
            events.append(("dialog_open", now))
            self.status = status

        def exec(self):
            events.append(("dialog_accept", None))
            return QDialog.DialogCode.Accepted

        def values(self):
            events.append(("dialog_values", None))
            return (
                self.status,
                "Synthetic audit review",
                "Local reviewer",
                "2026-08-02T12:01:00Z",
            )

    monkeypatch.setattr(app_module, "_DispositionDialog", AcceptDialog)
    monkeypatch.setattr(app_module, "_utc_now", current_time)
    monkeypatch.setattr(app_module, "save_protected_state", saved.append)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: (
            events.append(("invalid_confirmation", None))
            or QMessageBox.StandardButton.Yes
        ),
    )
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    window = create_window()
    window._protected_state_invalid = True
    window._scan_completed(_audit_outcome((finding,)))
    window.findings_table.selectRow(0)
    before = _window_transaction_state(window)

    window.false_positive_button.click()

    assert events == [
        ("clock", opened_at),
        ("dialog_open", opened_at),
        ("dialog_accept", None),
        ("dialog_values", None),
        ("invalid_confirmation", None),
        ("clock", commit_at),
    ]
    assert warnings == [("保存失败", "无法保存加密状态。")]
    assert saved == []
    assert _window_transaction_state(window) == before
    window.close()


@pytest.mark.parametrize(
    ("expiry_offset", "expected_saves"),
    ((timedelta(days=366), 1), (timedelta(days=366, seconds=1), 0)),
)
def test_create_enforces_exact_366_day_boundary_at_commit(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    expiry_offset: timedelta,
    expected_saves: int,
) -> None:
    finding = _disposition_finding()
    expiry = app_module._canonical_utc_seconds(EVALUATED_AT + expiry_offset)
    warnings = []
    saves = []

    class AcceptDialog:
        def __init__(self, parent, status, now):
            self.status = status

        def exec(self):
            return QDialog.DialogCode.Accepted

        def values(self):
            return (
                self.status,
                "Synthetic audit review",
                "Local reviewer",
                expiry,
            )

    monkeypatch.setattr(app_module, "_DispositionDialog", AcceptDialog)
    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    monkeypatch.setattr(app_module, "save_protected_state", saves.append)
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    window = create_window()
    window._scan_completed(_audit_outcome((finding,)))
    window.findings_table.selectRow(0)
    before = _window_transaction_state(window)

    window.false_positive_button.click()

    assert len(saves) == expected_saves
    if expected_saves:
        assert warnings == []
        assert window._dispositions[0].expires_at == expiry
    else:
        assert warnings == [("保存失败", "无法保存加密状态。")]
        assert _window_transaction_state(window) == before
    window.close()


def test_create_uses_one_post_dialog_time_for_record_snapshot_report_and_timer(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _disposition_finding()
    opened_at = EVALUATED_AT
    commit_at = EVALUATED_AT + timedelta(minutes=2)
    clock = iter((opened_at, commit_at))
    saved = []

    class AcceptDialog:
        def __init__(self, parent, status, now):
            assert now == opened_at
            self.status = status

        def exec(self):
            return QDialog.DialogCode.Accepted

        def values(self):
            return (
                self.status,
                "Synthetic audit review",
                "Local reviewer",
                "2026-08-02T13:00:00Z",
            )

    monkeypatch.setattr(app_module, "_DispositionDialog", AcceptDialog)
    monkeypatch.setattr(app_module, "_utc_now", lambda: next(clock))
    monkeypatch.setattr(app_module, "save_protected_state", saved.append)
    window = create_window()
    window._scan_completed(_audit_outcome((finding,)))
    window.findings_table.selectRow(0)

    window.false_positive_button.click()

    record = window._dispositions[0]
    payload = json.loads(window.report_json)
    assert len(saved) == 1
    assert record.created_at == "2026-08-02T12:02:00Z"
    assert saved[0].captured_at == record.created_at
    assert saved[0].dispositions == (record,)
    assert window._audit_outcome.evaluated_at == commit_at
    assert payload["findings"][0]["disposition"]["created_at"] == record.created_at
    assert window.findings_table.item(0, 4).text() == "误报"
    assert window._expiry_timer.isActive()
    assert window._expiry_timer.interval() == 3_480_000
    window.close()


def test_disposition_create_replace_and_withdraw_save_candidate_before_commit(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _disposition_finding()
    requested_statuses = []
    saved = []
    observed_before_save = []
    warnings = []

    class AcceptDialog:
        def __init__(self, parent, status, now):
            requested_statuses.append(status)
            self.status = status

        def exec(self):
            return QDialog.DialogCode.Accepted

        def values(self):
            return (
                self.status,
                "Synthetic audit review",
                "Local reviewer",
                "2026-08-03T12:00:00Z",
            )

    monkeypatch.setattr(app_module, "_DispositionDialog", AcceptDialog)
    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    monkeypatch.setattr(QMessageBox, "information", lambda *args: None)
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    window = create_window()
    original = _audit_outcome((finding,))
    window._scan_completed(original)
    window.findings_table.selectRow(0)

    def save_candidate(snapshot):
        observed_before_save.append(
            (
                window._dispositions,
                window._audit_outcome,
                window.report_json,
                window.findings_table.item(0, 4).text(),
                window.findings_table.currentRow(),
            )
        )
        saved.append(snapshot)

    monkeypatch.setattr(app_module, "save_protected_state", save_candidate)

    window.false_positive_button.click()

    assert warnings == []
    assert requested_statuses == [DispositionStatus.FALSE_POSITIVE]
    assert observed_before_save[0] == ((), original, original.report_json, "待处理", 0)
    assert len(saved) == 1
    assert saved[0].dispositions[0].status is DispositionStatus.FALSE_POSITIVE
    assert window._dispositions == saved[0].dispositions
    assert window._audit_outcome.findings is original.findings
    assert window._audit_outcome.score is original.score
    assert window._audit_outcome.score.total == 93
    assert window._audit_outcome.reviewed_score.total == 100
    assert window.findings_table.item(0, 4).text() == "误报"
    assert window.findings_table.currentRow() == 0
    payload = json.loads(window.report_json)
    assert payload["score"]["total"] == 93
    assert payload["reviewed_score"]["total"] == 100
    assert payload["findings"][0]["disposition"]["status"] == "false_positive"

    previous = window._audit_outcome
    window.accepted_risk_button.click()

    assert requested_statuses[-1] is DispositionStatus.ACCEPTED_RISK
    assert observed_before_save[1][0][0].status is DispositionStatus.FALSE_POSITIVE
    assert observed_before_save[1][1] is previous
    assert saved[1].dispositions[0].status is DispositionStatus.ACCEPTED_RISK
    assert window._audit_outcome.score is original.score
    assert window._audit_outcome.reviewed_score == original.score
    assert window.findings_table.item(0, 4).text() == "已接受风险"
    assert json.loads(window.report_json)["findings"][0]["disposition"][
        "status"
    ] == "accepted_risk"

    window.withdraw_button.click()

    assert saved[2].dispositions == ()
    assert window._dispositions == ()
    assert window._audit_outcome.score is original.score
    assert window._audit_outcome.reviewed_score == original.score
    assert window.findings_table.item(0, 4).text() == "待处理"
    assert window.findings_table.currentRow() == 0
    assert not window.withdraw_button.isEnabled()
    window.close()


def test_disposition_save_failure_rolls_back_every_visible_and_internal_value(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _disposition_finding()
    old_record = _disposition(finding, DispositionStatus.FALSE_POSITIVE)
    marker = "synthetic-private-save-marker"
    warnings = []

    class AcceptDialog:
        def __init__(self, parent, status, now):
            self.status = status

        def exec(self):
            return QDialog.DialogCode.Accepted

        def values(self):
            return (
                self.status,
                "Replacement audit review",
                "Replacement reviewer",
                "2026-08-04T12:00:00Z",
            )

    monkeypatch.setattr(app_module, "_DispositionDialog", AcceptDialog)
    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    monkeypatch.setattr(
        app_module,
        "save_protected_state",
        lambda snapshot: (_ for _ in ()).throw(StateStoreError(marker)),
    )
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    window = create_window()
    window._dispositions = (old_record,)
    window._protected_state_invalid = True
    window._scan_completed(_audit_outcome((finding,), (old_record,)))
    window.findings_table.selectRow(0)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    before = _window_transaction_state(window)

    window.accepted_risk_button.click()

    assert warnings == [("保存失败", "无法保存加密状态。")]
    assert marker not in repr(warnings)
    assert _window_transaction_state(window) == before
    window.close()


@pytest.mark.parametrize(
    "failure_point",
    ("score", "json", "html", "snapshot", "save", "commit_preparation"),
)
def test_disposition_transaction_prepares_every_outcome_before_save_and_rolls_back(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    finding = _disposition_finding()
    old_record = _disposition(finding, DispositionStatus.FALSE_POSITIVE)
    marker = f"private-{failure_point}-marker"
    warnings = []
    save_attempts = []

    class AcceptDialog:
        def __init__(self, parent, status, now):
            self.status = status

        def exec(self):
            return QDialog.DialogCode.Accepted

        def values(self):
            return (
                self.status,
                "Replacement audit review",
                "Replacement reviewer",
                "2026-08-04T12:00:00Z",
            )

    def fail(*args, **kwargs):
        raise RuntimeError(marker)

    def save(snapshot):
        save_attempts.append(snapshot)
        if failure_point == "save":
            fail()

    monkeypatch.setattr(app_module, "_DispositionDialog", AcceptDialog)
    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    monkeypatch.setattr(app_module, "save_protected_state", save)
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    window = create_window()
    window._dispositions = (old_record,)
    window._protected_state_invalid = True
    window._scan_completed(_audit_outcome((finding,), (old_record,)))
    window.findings_table.selectRow(0)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    if failure_point == "score":
        monkeypatch.setattr(app_module, "score", fail)
    elif failure_point == "json":
        monkeypatch.setattr(app_module, "render_json", fail)
    elif failure_point == "html":
        monkeypatch.setattr(app_module, "render_html", fail)
    elif failure_point == "snapshot":
        monkeypatch.setattr(app_module, "build_snapshot", fail)
    elif failure_point == "commit_preparation":
        monkeypatch.setattr(window, "_prepare_disposition_transaction", fail)
    before = _window_transaction_state(window)

    window.accepted_risk_button.click()

    assert len(save_attempts) == (1 if failure_point == "save" else 0)
    assert warnings == [("保存失败", "无法保存加密状态。")]
    assert marker not in repr(warnings)
    assert _window_transaction_state(window) == before
    window.close()


def test_disposition_transaction_builds_reports_and_snapshot_before_save(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _disposition_finding()
    events = []

    class AcceptDialog:
        def __init__(self, parent, status, now):
            self.status = status

        def exec(self):
            return QDialog.DialogCode.Accepted

        def values(self):
            return (
                self.status,
                "Synthetic audit review",
                "Local reviewer",
                "2026-08-03T12:00:00Z",
            )

    original_score = app_module.score
    original_json = app_module.render_json
    original_html = app_module.render_html
    original_snapshot = app_module.build_snapshot

    def traced(name, function):
        def wrapper(*args, **kwargs):
            events.append(name)
            return function(*args, **kwargs)

        return wrapper

    monkeypatch.setattr(app_module, "_DispositionDialog", AcceptDialog)
    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    monkeypatch.setattr(app_module, "score", traced("score", original_score))
    monkeypatch.setattr(app_module, "render_json", traced("json", original_json))
    monkeypatch.setattr(app_module, "render_html", traced("html", original_html))
    monkeypatch.setattr(
        app_module,
        "build_snapshot",
        traced("snapshot", original_snapshot),
    )
    monkeypatch.setattr(
        app_module,
        "save_protected_state",
        lambda snapshot: events.append("save"),
    )
    window = create_window()
    window._scan_completed(_audit_outcome((finding,)))
    window.findings_table.selectRow(0)

    window.false_positive_button.click()

    assert events == ["score", "json", "html", "snapshot", "save"]
    window.close()


@pytest.mark.parametrize(
    "failure_stage",
    (
        "set_reviewed_core",
        "status_ui",
        "report_ui",
        "selection",
        "timer_schedule",
        "timer_start",
    ),
)
def test_post_save_failures_roll_forward_persisted_core_without_save_warning(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    finding = _disposition_finding()
    marker = f"private-post-save-{failure_stage}-marker"
    saved = []
    warnings = []

    class AcceptDialog:
        def __init__(self, parent, status, now):
            self.status = status

        def exec(self):
            return QDialog.DialogCode.Accepted

        def values(self):
            return (
                self.status,
                "Synthetic audit review",
                "Local reviewer",
                "2026-08-03T12:00:00Z",
            )

    def fail(*args, **kwargs):
        raise RuntimeError(marker)

    monkeypatch.setattr(app_module, "_DispositionDialog", AcceptDialog)
    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    monkeypatch.setattr(app_module, "save_protected_state", saved.append)
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    window = create_window()
    original = _audit_outcome((finding,))
    window._scan_completed(original)
    window.findings_table.selectRow(0)

    if failure_stage == "set_reviewed_core":
        monkeypatch.setattr(window, "_set_reviewed_core", fail, raising=False)
    elif failure_stage == "status_ui":
        monkeypatch.setattr(window, "_refresh_disposition_ui", fail)
    elif failure_stage == "report_ui":
        monkeypatch.setattr(window, "_refresh_report", fail)
    elif failure_stage == "selection":
        original_select_row = QTableWidget.selectRow

        def fail_selection(table, row):
            if table is window.findings_table:
                fail()
            return original_select_row(table, row)

        monkeypatch.setattr(QTableWidget, "selectRow", fail_selection)
    elif failure_stage == "timer_schedule":
        monkeypatch.setattr(window, "_schedule_expiry_timer", fail)
    elif failure_stage == "timer_start":
        original_timer_start = QTimer.start

        def fail_timer_start(timer, *args):
            if timer is window._expiry_timer:
                fail()
            return original_timer_start(timer, *args)

        monkeypatch.setattr(QTimer, "start", fail_timer_start)

    window.false_positive_button.click()

    assert len(saved) == 1
    persisted = saved[0].dispositions
    assert window._dispositions == persisted
    assert not window._protected_state_invalid
    assert window._audit_outcome.findings is original.findings
    assert window._audit_outcome.score is original.score
    assert window._audit_outcome.reviewed_score.total == 100
    assert window._audit_outcome.report_json == window.report_json
    assert window._audit_outcome.report_html == window.report_html
    payload = json.loads(window.report_json)
    assert payload["findings"][0]["disposition"]["status"] == "false_positive"
    expected_status = "状态待刷新" if failure_stage == "status_ui" else "误报"
    assert window.findings_table.item(0, 4).text() == expected_status
    if failure_stage == "report_ui":
        assert window.report_browser.toPlainText() == "报告已更新，界面暂时无法刷新。"
    if failure_stage == "selection":
        assert window.findings_table.currentRow() == -1
        assert window.findings_table.selectedIndexes() == []
        assert not window.false_positive_button.isEnabled()
        assert not window.accepted_risk_button.isEnabled()
        assert not window.withdraw_button.isEnabled()
    else:
        assert window.findings_table.currentRow() == 0
        assert {index.row() for index in window.findings_table.selectedIndexes()} == {0}
    if failure_stage == "timer_schedule":
        assert window._expiry_timer.isActive()
        assert window._expiry_timer.interval() == 60_000
    elif failure_stage == "timer_start":
        assert not window._expiry_timer.isActive()
    else:
        assert window._expiry_timer.isActive()
    assert warnings == []
    ui_failed = failure_stage != "set_reviewed_core"
    assert window._refresh_failure_notified is ui_failed
    expected_message = (
        "处置已保存，界面刷新受限。"
        if ui_failed
        else "审计未完整：发现 1 项风险，覆盖率 75%；不能判定为安全。"
    )
    assert window.status_label.text() == expected_message
    visible = " ".join(
        (
            window.status_label.text(),
            window.report_browser.toPlainText(),
            window.findings_table.item(0, 4).text(),
        )
    )
    assert marker not in visible
    window.close()


@pytest.mark.parametrize("failure_point", ("clock", "dialog_values"))
def test_create_callback_contains_unexpected_clock_and_dialog_errors(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    finding = _disposition_finding()
    marker = f"private-{failure_point}-marker"
    warnings = []
    saves = []

    class AcceptDialog:
        def __init__(self, parent, status, now):
            self.status = status

        def exec(self):
            return QDialog.DialogCode.Accepted

        def values(self):
            raise RuntimeError(marker)

    monkeypatch.setattr(app_module, "_DispositionDialog", AcceptDialog)
    if failure_point == "clock":
        monkeypatch.setattr(
            app_module,
            "_utc_now",
            lambda: (_ for _ in ()).throw(RuntimeError(marker)),
        )
    else:
        monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    monkeypatch.setattr(app_module, "save_protected_state", saves.append)
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    window = create_window()
    window._scan_completed(_audit_outcome((finding,)))
    window.findings_table.selectRow(0)
    before = _window_transaction_state(window)

    window.false_positive_button.click()

    assert warnings == [("保存失败", "无法保存加密状态。")]
    assert marker not in repr(warnings)
    assert saves == []
    assert _window_transaction_state(window) == before
    window.close()


@pytest.mark.parametrize("failure_point", ("clock", "snapshot", "save"))
def test_explicit_save_callback_contains_every_unexpected_failure(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    finding = _disposition_finding()
    marker = f"private-explicit-{failure_point}-marker"
    warnings = []
    save_attempts = []

    def fail(*args, **kwargs):
        raise RuntimeError(marker)

    def save(snapshot):
        save_attempts.append(snapshot)
        if failure_point == "save":
            fail()

    monkeypatch.setattr(app_module, "_utc_now", fail if failure_point == "clock" else lambda: EVALUATED_AT)
    monkeypatch.setattr(app_module, "save_protected_state", save)
    if failure_point == "snapshot":
        monkeypatch.setattr(app_module, "build_snapshot", fail)
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *args: None)
    window = create_window()
    window._protected_state_invalid = True
    window._scan_completed(_audit_outcome((finding,)))
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    before = _window_transaction_state(window)

    window.protected_state_button.click()

    assert len(save_attempts) == (1 if failure_point == "save" else 0)
    assert warnings == [("保存失败", "无法保存加密状态。")]
    assert marker not in repr(warnings)
    assert _window_transaction_state(window) == before
    window.close()


def test_withdraw_callback_contains_unexpected_confirmation_failure(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _disposition_finding()
    record = _disposition(finding, DispositionStatus.FALSE_POSITIVE)
    marker = "private-withdraw-question-marker"
    warnings = []
    saves = []
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(marker)),
    )
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    monkeypatch.setattr(app_module, "save_protected_state", saves.append)
    window = create_window()
    window._dispositions = (record,)
    window._scan_completed(_audit_outcome((finding,), (record,)))
    window.findings_table.selectRow(0)
    before = _window_transaction_state(window)

    window.withdraw_button.click()

    assert warnings == [("保存失败", "无法保存加密状态。")]
    assert marker not in repr(warnings)
    assert saves == []
    assert _window_transaction_state(window) == before
    window.close()


def test_invalid_state_replacement_requires_yes_for_disposition_and_explicit_save(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _disposition_finding()
    answers = iter(
        (
            QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
    )
    saves = []
    flags_during_save = []
    warnings = []

    class AcceptDialog:
        def __init__(self, parent, status, now):
            self.status = status

        def exec(self):
            return QDialog.DialogCode.Accepted

        def values(self):
            return (
                self.status,
                "Synthetic audit review",
                "Local reviewer",
                "2026-08-03T12:00:00Z",
            )

    monkeypatch.setattr(app_module, "_DispositionDialog", AcceptDialog)
    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    monkeypatch.setattr(QMessageBox, "information", lambda *args: None)
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda parent, title, message: warnings.append((title, message)),
    )
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: next(answers),
    )
    window = create_window()
    window._protected_state_invalid = True
    window._scan_completed(_audit_outcome((finding,)))
    window.findings_table.selectRow(0)

    def save_candidate(snapshot):
        flags_during_save.append(window._protected_state_invalid)
        saves.append(snapshot)

    monkeypatch.setattr(app_module, "save_protected_state", save_candidate)
    before = _window_transaction_state(window)

    window.false_positive_button.click()
    assert warnings == []
    assert saves == []
    assert _window_transaction_state(window) == before

    window.false_positive_button.click()
    assert len(saves) == 1
    assert flags_during_save == [True]
    assert not window._protected_state_invalid

    explicit = create_window()
    explicit._protected_state_invalid = True
    explicit._scan_completed(_audit_outcome((finding,)))
    explicit_before = _window_transaction_state(explicit)

    def save_explicit(snapshot):
        flags_during_save.append(explicit._protected_state_invalid)
        saves.append(snapshot)

    monkeypatch.setattr(app_module, "save_protected_state", save_explicit)

    explicit.protected_state_button.click()
    assert len(saves) == 1
    assert _window_transaction_state(explicit) == explicit_before

    explicit.protected_state_button.click()
    assert len(saves) == 2
    assert flags_during_save == [True, True]
    assert not explicit._protected_state_invalid
    explicit.close()
    window.close()


def test_withdrawal_and_explicit_save_capture_time_after_confirmations(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _disposition_finding()
    record = _disposition(finding, DispositionStatus.FALSE_POSITIVE)
    events = []

    def answer_question(parent, title, message, *args, **kwargs):
        events.append(("question", title))
        return QMessageBox.StandardButton.Yes

    def current_time():
        events.append(("clock", None))
        return EVALUATED_AT

    monkeypatch.setattr(QMessageBox, "question", answer_question)
    monkeypatch.setattr(QMessageBox, "information", lambda *args: None)
    monkeypatch.setattr(app_module, "_utc_now", current_time)
    monkeypatch.setattr(
        app_module,
        "save_protected_state",
        lambda snapshot: events.append(("save", snapshot.captured_at)),
    )
    window = create_window()
    window._dispositions = (record,)
    window._protected_state_invalid = True
    window._scan_completed(_audit_outcome((finding,), (record,)))
    window.findings_table.selectRow(0)

    window.withdraw_button.click()

    assert events == [
        ("question", "撤销处置"),
        ("question", "替换无效状态"),
        ("clock", None),
        ("save", "2026-08-02T12:00:00Z"),
    ]

    events.clear()
    explicit = create_window()
    explicit._protected_state_invalid = True
    explicit._scan_completed(_audit_outcome((finding,)))

    explicit.protected_state_button.click()

    assert events == [
        ("question", "替换无效状态"),
        ("clock", None),
        ("save", "2026-08-02T12:00:00Z"),
    ]
    explicit.close()
    window.close()


def test_expiry_timer_refreshes_scores_reports_and_status_without_writing(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _disposition_finding()
    active = _disposition(
        finding,
        DispositionStatus.FALSE_POSITIVE,
        expires_at="2026-08-02T12:00:02Z",
    )
    clock = [EVALUATED_AT]
    saves = []
    monkeypatch.setattr(app_module, "_utc_now", lambda: clock[0])
    monkeypatch.setattr(app_module, "save_protected_state", saves.append)
    window = create_window()
    window._dispositions = (active,)
    window._scan_completed(_audit_outcome((finding,), (active,)))
    window.findings_table.selectRow(0)

    assert window._expiry_timer.isSingleShot()
    assert window._expiry_timer.isActive()
    assert 1 <= window._expiry_timer.interval() <= 2000
    assert window.findings_table.item(0, 4).text() == "误报"
    assert window._audit_outcome.reviewed_score.total == 100

    clock[0] = EVALUATED_AT + timedelta(seconds=2)
    window._handle_expiry_timeout()

    assert window._dispositions == (active,)
    assert window.findings_table.item(0, 4).text() == "已过期"
    assert window._audit_outcome.reviewed_score == window._audit_outcome.score
    assert json.loads(window.report_json)["findings"][0]["disposition"][
        "status"
    ] == "expired"
    assert not window._expiry_timer.isActive()
    assert saves == []

    accepted = _disposition(
        finding,
        DispositionStatus.ACCEPTED_RISK,
        created_at="2026-08-02T12:00:02Z",
        expires_at="2027-02-18T12:00:02Z",
    )
    window._dispositions = (accepted,)
    prepared = window._reviewed_outcome((accepted,), clock[0])
    window._audit_outcome = prepared
    window.report_json = prepared.report_json
    window.report_html = prepared.report_html
    window._refresh_reviewed_ui_no_throw(
        prepared.evaluated_at,
        window.findings_table.currentRow(),
        failure_message="处置已保存，界面刷新受限。",
    )

    assert window.findings_table.item(0, 4).text() == "已接受风险"
    assert window._audit_outcome.reviewed_score == window._audit_outcome.score
    assert window._expiry_timer.isActive()
    assert window._expiry_timer.interval() == 86_400_000

    clock[0] += timedelta(days=1)
    window._handle_expiry_timeout()
    assert window._expiry_timer.isActive()
    assert window._expiry_timer.interval() == 86_400_000
    assert window._dispositions == (accepted,)
    assert saves == []

    window._invalidate_report()
    assert not window._expiry_timer.isActive()
    window.close()


def test_filter_expiry_moves_finding_between_disposition_views_at_same_time(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _disposition_finding()
    active = _disposition(
        finding,
        DispositionStatus.FALSE_POSITIVE,
        expires_at="2026-08-02T12:00:02Z",
    )
    clock = [EVALUATED_AT]
    filter_times = []
    saves = []
    real_filter = app_module.filter_findings

    def tracking_filter(findings, dispositions, filters, *, now):
        filter_times.append(now)
        return real_filter(findings, dispositions, filters, now=now)

    monkeypatch.setattr(app_module, "_utc_now", lambda: clock[0])
    monkeypatch.setattr(app_module, "filter_findings", tracking_filter)
    monkeypatch.setattr(app_module, "save_protected_state", saves.append)
    window = create_window()
    window._dispositions = (active,)
    window._scan_completed(_audit_outcome((finding,), (active,)))
    window.disposition_filter_combo.setCurrentIndex(
        window.disposition_filter_combo.findData("false_positive")
    )
    qapp.processEvents()

    assert window.findings_count_label.text() == "显示 1 / 共 1 项发现"
    assert window.findings_table.item(0, 4).text() == "误报"

    clock[0] = EVALUATED_AT + timedelta(seconds=2)
    window._handle_expiry_timeout()

    assert window._audit_outcome.evaluated_at == clock[0]
    assert window._audit_outcome.reviewed_score == window._audit_outcome.score
    assert json.loads(window.report_json)["findings"][0]["disposition"][
        "status"
    ] == "expired"
    assert filter_times[-1] == clock[0]
    assert window.findings_count_label.text() == "显示 0 / 共 1 项发现"
    assert window.findings_table.rowCount() == 0
    assert window.guidance_browser.toPlainText() == "当前筛选条件下无匹配风险发现。"

    window.disposition_filter_combo.setCurrentIndex(
        window.disposition_filter_combo.findData("expired")
    )
    qapp.processEvents()

    assert filter_times[-1] == clock[0]
    assert window.findings_count_label.text() == "显示 1 / 共 1 项发现"
    assert window.findings_table.rowCount() == 1
    assert window.findings_table.item(0, 4).text() == "已过期"
    assert window._row_findings == [finding]
    assert window._dispositions == (active,)
    assert saves == []
    window.close()


@pytest.mark.parametrize("failure_point", ("clock", "review", "report_ui"))
def test_expiry_timer_contains_failure_with_bounded_retry_or_roll_forward(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    finding = _disposition_finding()
    active = _disposition(
        finding,
        DispositionStatus.FALSE_POSITIVE,
        expires_at="2026-08-02T12:00:10Z",
    )
    marker = f"private-timer-{failure_point}-marker"
    saves = []
    monkeypatch.setattr(app_module, "save_protected_state", saves.append)
    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    window = create_window()
    window._dispositions = (active,)
    window._scan_completed(_audit_outcome((finding,), (active,)))
    window.findings_table.selectRow(0)
    window._expiry_timer.start(4321)
    if failure_point == "clock":
        monkeypatch.setattr(
            app_module,
            "_utc_now",
            lambda: (_ for _ in ()).throw(RuntimeError(marker)),
        )
    else:
        target = "_reviewed_outcome" if failure_point == "review" else "_refresh_report"
        if failure_point == "report_ui":
            monkeypatch.setattr(
                app_module,
                "_utc_now",
                lambda: EVALUATED_AT + timedelta(seconds=10),
            )
        monkeypatch.setattr(
            window,
            target,
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(marker)),
        )
    previous_outcome = window._audit_outcome
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(marker)),
    )

    window._handle_expiry_timeout()

    assert saves == []
    assert window._dispositions == (active,)
    assert window._refresh_failure_notified
    assert window.status_label.text() == "处置状态刷新受限，请复核当前界面状态。"
    if failure_point == "report_ui":
        assert window._audit_outcome.evaluated_at == EVALUATED_AT + timedelta(seconds=10)
        assert window._audit_outcome.reviewed_score == window._audit_outcome.score
        assert window.findings_table.item(0, 4).text() == "已过期"
        assert window.report_browser.toPlainText() == "报告已更新，界面暂时无法刷新。"
        assert not window._expiry_timer.isActive()
    else:
        assert window._audit_outcome is previous_outcome
        assert window.findings_table.item(0, 4).text() == "误报"
        assert window._expiry_timer.isActive()
        assert window._expiry_timer.interval() == 60_000
    assert marker not in " ".join(
        (window.status_label.text(), window.report_browser.toPlainText())
    )
    window.close()


def test_expiry_timer_success_clears_failure_and_restores_audit_status(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _disposition_finding()
    active = _disposition(
        finding,
        DispositionStatus.FALSE_POSITIVE,
        expires_at="2026-08-02T12:00:10Z",
    )
    attempts = 0

    def current_time():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("private-recovery-marker")
        return EVALUATED_AT + timedelta(seconds=1)

    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    window = create_window()
    window._dispositions = (active,)
    window._scan_completed(_audit_outcome((finding,), (active,)))
    window.findings_table.selectRow(0)
    monkeypatch.setattr(app_module, "_utc_now", current_time)

    window._handle_expiry_timeout()
    assert window._refresh_failure_notified
    assert window.status_label.text() == "处置状态刷新受限，请复核当前界面状态。"

    window._handle_expiry_timeout()

    assert attempts == 2
    assert not window._refresh_failure_notified
    assert (
        window.status_label.text()
        == "审计未完整：发现 1 项风险，覆盖率 75%；不能判定为安全。"
    )
    assert window.findings_table.item(0, 4).text() == "误报"
    assert window._expiry_timer.isActive()
    assert window._expiry_timer.interval() == 9_000
    window.close()


def test_expiry_timer_retries_normal_status_after_one_shot_label_failure(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _disposition_finding()
    active = _disposition(
        finding,
        DispositionStatus.FALSE_POSITIVE,
        expires_at="2026-08-02T12:00:10Z",
    )
    normal_status = "审计未完整：发现 1 项风险，覆盖率 75%；不能判定为安全。"
    clock_attempts = 0
    normal_status_attempts = 0
    original_set_text = QLabel.setText

    def current_time():
        nonlocal clock_attempts
        clock_attempts += 1
        if clock_attempts == 1:
            raise RuntimeError("private-clock-marker")
        return EVALUATED_AT + timedelta(seconds=1)

    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    window = create_window()
    window._dispositions = (active,)
    window._scan_completed(_audit_outcome((finding,), (active,)))
    window.findings_table.selectRow(0)

    def one_shot_label_failure(label, text):
        nonlocal normal_status_attempts
        if label is window.status_label and text == normal_status:
            normal_status_attempts += 1
            if normal_status_attempts == 1:
                raise RuntimeError("private-label-marker")
        return original_set_text(label, text)

    monkeypatch.setattr(app_module, "_utc_now", current_time)
    monkeypatch.setattr(QLabel, "setText", one_shot_label_failure)

    window._handle_expiry_timeout()
    assert window._refresh_failure_notified
    assert window.status_label.text() == "处置状态刷新受限，请复核当前界面状态。"

    window._handle_expiry_timeout()
    assert window._refresh_failure_notified
    assert window.status_label.text() == "处置状态刷新受限，请复核当前界面状态。"

    window._handle_expiry_timeout()

    assert clock_attempts == 3
    assert normal_status_attempts == 2
    assert not window._refresh_failure_notified
    assert window.status_label.text() == normal_status
    window.close()


def test_repeated_timer_failures_never_escape_spin_or_repeat_notification(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _disposition_finding()
    active = _disposition(
        finding,
        DispositionStatus.FALSE_POSITIVE,
        expires_at="2026-08-02T12:00:10Z",
    )
    marker = "private-repeated-timer-marker"
    timer_starts = []
    notification_attempts = []
    original_timer_start = QTimer.start
    original_label_set_text = QLabel.setText

    monkeypatch.setattr(app_module, "_utc_now", lambda: EVALUATED_AT)
    window = create_window()
    window._dispositions = (active,)
    window._scan_completed(_audit_outcome((finding,), (active,)))
    window.findings_table.selectRow(0)
    previous_outcome = window._audit_outcome

    monkeypatch.setattr(
        app_module,
        "_utc_now",
        lambda: (_ for _ in ()).throw(RuntimeError(marker)),
    )

    def fail_timer_start(timer, interval):
        if timer is window._expiry_timer:
            timer_starts.append(interval)
            raise RuntimeError(marker)
        return original_timer_start(timer, interval)

    def fail_notification(label, text):
        if label is window.status_label:
            notification_attempts.append(text)
            raise RuntimeError(marker)
        return original_label_set_text(label, text)

    monkeypatch.setattr(QTimer, "start", fail_timer_start)
    monkeypatch.setattr(QLabel, "setText", fail_notification)
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError(marker)),
    )

    for _ in range(3):
        window._handle_expiry_timeout()

    assert window._audit_outcome is previous_outcome
    assert window._dispositions == (active,)
    assert timer_starts == [60_000, 60_000, 60_000]
    assert notification_attempts == ["处置状态刷新受限，请复核当前界面状态。"]
    assert window._refresh_failure_notified
    assert not window._expiry_timer.isActive()
    window.close()


def test_openai_local_config_suffixes_are_supported() -> None:
    assert all(
        selector in app_module.SUPPORTED_SUFFIXES
        for selector in (".env", ".toml")
    )


def test_openai_env_override_is_masked_end_to_end(qapp, tmp_path: Path) -> None:
    endpoint = "https://synthetic-provider.invalid/v1"
    (tmp_path / ".env").write_text(
        f"export OPENAI_BASE_URL={endpoint}\n",
        encoding="utf-8",
    )

    outcome = _run_audit(
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


def test_openai_fixed_remediation_is_explicit_and_reversible(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / ".env"
    original = b"OPENAI_BASE_URL=https://synthetic-provider.invalid/v1\n"
    target.write_bytes(original)
    finding = Finding(
        rule_id="OPENAI_BASE_URL_OVERRIDE",
        domain=RiskDomain.SUPPLY_CHAIN,
        severity=Severity.LOW,
        root_fingerprint="a" * 64,
        evidence=(
            Evidence(
                ".env",
                "b" * 64,
                "OpenAI API base URL override configured",
            ),
        ),
    )
    window = create_window()
    window._scan_completed(_audit_outcome((finding,), coverage=1.0, confidence=1.0, limits=()))
    window._report_roots = (tmp_path,)
    window.findings_table.selectRow(0)
    qapp.processEvents()

    assert window.remediation_button.isEnabled()
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *args, **kwargs: (str(target), "Configuration"),
    )
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)

    window.remediation_button.click()

    assert target.read_bytes() == b"OPENAI_BASE_URL=https://api.openai.com/v1\n"
    assert target.with_name(".env.agentguardian.bak").read_bytes() == original
    assert window.rollback_button.isEnabled()

    window.rollback_button.click()

    assert target.read_bytes() == original
    assert not target.with_name(".env.agentguardian.bak").exists()
    assert not window.rollback_button.isEnabled()
    window.close()


def test_fixed_remediation_stays_disabled_for_non_allowlisted_findings(qapp) -> None:
    finding = _synthetic_finding(1)
    window = create_window()
    window._scan_completed(_audit_outcome((finding,), coverage=1.0, confidence=1.0, limits=()))
    window.findings_table.selectRow(0)
    qapp.processEvents()

    assert not window.remediation_button.isEnabled()
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

    first = _run_audit(
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
    second = _run_audit(
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

    accepted = _run_audit(
        (root,),
        disposition_key=disposition_key,
        dispositions=(
            _disposition(first_finding, DispositionStatus.ACCEPTED_RISK),
        ),
        evaluated_at=EVALUATED_AT,
    )
    expired = _run_audit(
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
    moved = _run_audit(
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


def test_production_audit_evaluates_expiry_after_detection_finishes(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "scan.txt"
    path.write_text("synthetic", encoding="utf-8")
    finding = _disposition_finding()
    record = _disposition(
        finding,
        DispositionStatus.FALSE_POSITIVE,
        created_at="2026-08-02T11:00:00Z",
        expires_at="2026-08-02T12:01:00Z",
    )
    after_scan = EVALUATED_AT + timedelta(minutes=2)
    events = []
    saves = []

    def discover(*args, **kwargs):
        events.append("discover")
        return _discovery_result((path,))

    def detect(*args, **kwargs):
        events.append("detect")
        return FileDetectionResult((finding,), True, ())

    def current_time():
        events.append("clock")
        return after_scan

    monkeypatch.setattr(app_module, "discover_files", discover)
    monkeypatch.setattr(app_module, "detect_file", detect)
    monkeypatch.setattr(app_module, "_utc_now", current_time)
    monkeypatch.setattr(app_module, "save_protected_state", saves.append)

    outcome = _run_audit(
        (tmp_path,),
        disposition_key=DISPOSITION_KEY,
        dispositions=(record,),
    )

    assert events == ["discover", "detect", "clock"]
    assert outcome.evaluated_at == after_scan
    assert outcome.score == score((finding,), coverage=1.0, confidence=1.0)
    assert outcome.reviewed_score == outcome.score
    assert json.loads(outcome.report_json)["findings"][0]["disposition"][
        "status"
    ] == "expired"
    assert "Disposition status: expired" in outcome.report_html

    window = create_window()
    window._dispositions = (record,)
    window._scan_completed(outcome)

    assert window.findings_table.item(0, 4).text() == "已过期"
    assert window._audit_outcome.reviewed_score == window._audit_outcome.score
    assert not window._expiry_timer.isActive()
    assert saves == []
    window.close()


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

    outcome = _run_audit(
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
        _run_audit(
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
    worker = app_module.AuditWorker(
        (tmp_path,),
        app_module._scope_preview_for((tmp_path,)),
        DISPOSITION_KEY,
        (),
    )
    worker.failed.connect(failures.append)
    monkeypatch.setattr(
        app_module.secrets,
        "token_bytes",
        lambda length: (_ for _ in ()).throw(RuntimeError(marker)),
    )

    worker.run()

    assert failures == ["scan_failed"]
    assert marker not in repr(failures)


def test_worker_uses_accepted_preview_after_selector_and_cap_replacement(
    qapp,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "accepted-root"
    root.mkdir()
    files = tuple(root / name for name in ("a.txt", "b.txt"))
    for path in files:
        path.write_bytes(b"xx")
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(root),
    )
    window = create_window()
    window.folder_button.click()
    _approve_current_scope(window)
    accepted_preview = window._scope_preview
    assert accepted_preview is not None
    worker = app_module.AuditWorker(
        (root,),
        accepted_preview,
        DISPOSITION_KEY,
        (),
    )
    captured = {}
    completed = []
    failures = []
    worker.completed.connect(completed.append)
    worker.failed.connect(failures.append)

    def discover(roots, selectors, *, max_files, max_entries):
        captured.update(
            roots=tuple(roots),
            selectors=selectors,
            max_files=max_files,
            max_entries=max_entries,
        )
        return _discovery_result(files)

    monkeypatch.setattr(app_module, "discover_files", discover)
    monkeypatch.setattr(
        app_module,
        "detect_file",
        lambda path, *, scan_key, disposition_key: FileDetectionResult(
            (_synthetic_finding(1 if path == files[0] else 2),),
            True,
            (),
        ),
    )
    monkeypatch.setattr(app_module, "SUPPORTED_SUFFIXES", (".replacement",))
    monkeypatch.setattr(app_module, "MAX_AUDIT_FILES", 1)
    monkeypatch.setattr(app_module, "MAX_AUDIT_ENTRIES", 2)
    monkeypatch.setattr(app_module, "MAX_AUDIT_BYTES", 1)
    monkeypatch.setattr(app_module, "MAX_AUDIT_FINDINGS", 1)
    monkeypatch.setattr(app_module, "MAX_AUDIT_EVIDENCE", 1)

    worker.run()

    assert failures == []
    assert len(completed) == 1
    assert captured == {
        "roots": (root,),
        "selectors": accepted_preview.selectors,
        "max_files": accepted_preview.max_files,
        "max_entries": accepted_preview.max_entries,
    }
    assert completed[0].findings == (
        _synthetic_finding(1),
        _synthetic_finding(2),
    )
    assert completed[0].score.coverage == 1.0
    assert completed[0].score.limits == ()
    assert str(root).casefold() not in repr(accepted_preview).casefold()
    assert str(root).casefold() not in repr(worker).casefold()
    window.close()


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
        _run_audit(
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
    outcome = _run_audit(
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
        def __init__(self, roots, scope_preview, disposition_key, dispositions):
            super().__init__(
                roots,
                scope_preview,
                disposition_key,
                dispositions,
            )
            worker_context.update(
                roots=self._roots,
                scope_preview=self._scope_preview,
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
    _approve_current_scope(window)
    window.scan_button.click()
    assert worker_context["roots"] == (root,)
    assert worker_context["scope_preview"] is window._scope_preview
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
    outcome = _run_audit(
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
    assert window._scope_preview.root_count == 1
    assert window._scope_preview.root_names == ("selected-root",)
    assert not window.supported_data_checkbox.isChecked()
    assert not window.scope_consent_checkbox.isChecked()
    assert window._scope_consent is None
    assert not window.scan_button.isEnabled()

    preview_text = " ".join(
        label.text()
        for label in (
            window.scope_roots_label,
            window.scope_selectors_label,
            window.scope_limits_label,
            window.scope_exclusions_label,
            window.scope_mode_label,
        )
    )
    assert "selected-root" in preview_text
    assert "支持后缀" in preview_text
    assert "精确文件名" in preview_text
    assert ".json" in preview_text
    assert ".env" in preview_text
    assert "10,000" in preview_text
    assert "50,000" in preview_text
    assert "536,870,912" in preview_text
    assert "2,000" in preview_text
    assert "4,000" in preview_text
    assert "UNC" in preview_text
    assert "驱动器根目录" in preview_text
    assert "重解析" in preview_text
    assert "本地" in preview_text
    assert "只读" in preview_text
    assert "人工指引" in preview_text
    assert "API" in preview_text

    selected_text = str(selected).casefold()
    for widget in window.findChildren(QWidget):
        surfaces = [
            widget.toolTip(),
            widget.accessibleName(),
            widget.accessibleDescription(),
            repr(widget),
        ]
        text_method = getattr(widget, "text", None)
        if callable(text_method):
            surfaces.append(text_method())
        assert all(selected_text not in surface.casefold() for surface in surfaces)

    _approve_current_scope(window)
    assert str(selected).casefold() not in repr(window._scope_preview).casefold()
    assert str(selected).casefold() not in repr(window._scope_consent).casefold()

    window.resize(960, 640)
    window.show()
    qapp.processEvents()
    preview_widgets = (
        window.scope_roots_label,
        window.scope_selectors_label,
        window.scope_limits_label,
        window.scope_exclusions_label,
        window.scope_mode_label,
        window.supported_data_checkbox,
        window.supported_data_disclosure_label,
        window.scope_consent_checkbox,
    )
    assert all(widget.isVisible() for widget in preview_widgets)
    for upper, lower in zip(preview_widgets, preview_widgets[1:]):
        assert not _global_rect(upper).intersects(_global_rect(lower))
    available_width = window.width() - window.sidebar.width() - 48
    assert available_width == 724
    assert window.supported_data_checkbox.sizeHint().width() <= available_width
    assert "医疗" not in window.supported_data_checkbox.text()
    assert "医疗" in window.supported_data_checkbox.toolTip()
    assert "国家秘密" in window.supported_data_checkbox.accessibleDescription()
    disclosure = window.supported_data_disclosure_label
    assert disclosure.objectName() == "supportedDataDisclosure"
    assert disclosure.wordWrap()
    assert disclosure.width() <= available_width
    for required_class in (
        "医疗",
        "金融",
        "身份/生物识别",
        "法律特权",
        "客户数据",
        "其他受监管或高敏感真实数据",
    ):
        assert required_class in disclosure.text()
        assert required_class in disclosure.accessibleDescription()
    assert not _global_rect(window.scope_consent_checkbox).intersects(
        _global_rect(window.scan_button)
    )
    window.close()


def test_supported_data_boundary_is_a_separate_required_confirmation(
    qapp, tmp_path
):
    window = create_window()

    assert not window.supported_data_checkbox.isChecked()
    assert not window.browser_button.isEnabled()
    assert not window.clipboard_button.isEnabled()

    window.supported_data_checkbox.setChecked(True)

    assert not window._personal_scope_ready()
    assert not window.browser_button.isEnabled()
    assert not window.clipboard_button.isEnabled()
    assert not window.scan_button.isEnabled()

    window._set_scope_roots(
        (tmp_path / "ordinary-project",),
        status="ready",
    )

    assert not window.supported_data_checkbox.isChecked()
    assert not window.scope_consent_checkbox.isChecked()
    window.scope_consent_checkbox.setChecked(True)
    assert not window.scan_button.isEnabled()
    window.supported_data_checkbox.setChecked(True)
    assert window.scan_button.isEnabled()
    assert window._personal_scope_ready()
    assert window.browser_button.isEnabled()
    assert window.clipboard_button.isEnabled()

    window.supported_data_checkbox.setChecked(False)

    assert not window.scope_consent_checkbox.isChecked()
    assert window._scope_consent is None
    assert not window.scan_button.isEnabled()
    assert not window.browser_button.isEnabled()
    assert not window.clipboard_button.isEnabled()
    window.close()


def test_personal_scope_readiness_rejects_no_preview_unchecked_and_stale_consent(
    qapp, tmp_path
):
    window = create_window()
    window.supported_data_checkbox.setChecked(True)
    assert not window._personal_scope_ready()

    current_root = tmp_path / "current-project"
    stale_root = tmp_path / "stale-project"
    window._set_scope_roots((current_root,), status="ready")
    window.supported_data_checkbox.setChecked(True)
    assert not window.scope_consent_checkbox.isChecked()
    assert not window._personal_scope_ready()

    window.scope_consent_checkbox.setChecked(True)
    assert window._personal_scope_ready()

    stale_preview = app_module._scope_preview_for((stale_root,))
    window._scope_consent = app_module.bind_scope_consent(stale_preview)
    window._update_optional_audit_enabled()
    assert not window._personal_scope_ready()
    assert not window.browser_button.isEnabled()
    assert not window.clipboard_button.isEnabled()
    window.close()


def test_folder_eligibility_failure_clears_both_confirmations_without_leak(
    qapp, monkeypatch
):
    rejected = r"C:\Users\Alice\Downloads"
    window = create_window()
    window.supported_data_checkbox.setChecked(True)
    window.scope_consent_checkbox.setEnabled(True)
    window.scope_consent_checkbox.setChecked(True)
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: rejected,
    )

    window.folder_button.click()

    assert window._roots == ()
    assert not window.supported_data_checkbox.isChecked()
    assert not window.scope_consent_checkbox.isChecked()
    assert not window.scan_button.isEnabled()
    assert rejected.casefold() not in window.status_label.text().casefold()
    assert rejected.casefold() not in window.root_display_label.text().casefold()
    window.close()


def test_known_config_button_adds_allowlisted_roots_without_exposing_paths(
    qapp, monkeypatch, tmp_path
):
    selected = tmp_path / "selected-root"
    known = tmp_path / "known-config"
    selected.mkdir()
    known.mkdir()
    monkeypatch.setattr(
        app_module,
        "known_config_roots",
        lambda environ: [known],
    )
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(selected),
    )

    window = create_window()
    window.folder_button.click()
    window.known_config_button.click()

    assert window._roots == (selected, known)
    assert window._scope_preview.root_count == 2
    assert set(window._scope_preview.root_names) == {
        "selected-root",
        "known-config",
    }
    assert not window.scope_consent_checkbox.isChecked()
    assert not window.scan_button.isEnabled()
    assert str(known).casefold() not in repr(window._scope_preview).casefold()
    assert str(known).casefold() not in window.root_display_label.text().casefold()
    assert "known-config" in window.scope_roots_label.text()
    window.close()


def test_scope_change_and_rejected_selection_revoke_consent_and_results(
    qapp, monkeypatch, tmp_path
):
    first = tmp_path / "first-root"
    second = tmp_path / "second-root"
    first.mkdir()
    second.mkdir()
    selections = iter((str(first), str(second), ""))
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: next(selections),
    )
    window = create_window()

    window.folder_button.click()
    _approve_current_scope(window)
    window.report_json = "old json"
    window.report_html = "old html"
    window.findings_table.setRowCount(1)
    window._comparison_state = object()

    window.folder_button.click()

    assert window._roots == (second,)
    assert window.root_display_label.text() == "second-root"
    assert not window.supported_data_checkbox.isChecked()
    assert not window.scope_consent_checkbox.isChecked()
    assert window._scope_consent is None
    assert not window.scan_button.isEnabled()
    assert window.report_json == ""
    assert window.report_html == ""
    assert window.findings_table.rowCount() == 0
    assert window._comparison_state is None

    _approve_current_scope(window)
    window.report_json = "new old json"
    window._comparison_state = object()
    window.folder_button.click()

    assert window._roots == ()
    assert window.root_display_label.text() == "尚未选择"
    assert not window.supported_data_checkbox.isChecked()
    assert not window.scope_consent_checkbox.isChecked()
    assert window._scope_consent is None
    assert not window.scan_button.isEnabled()
    assert window.report_json == ""
    assert window._comparison_state is None
    assert window.status_label.text() == "未选择有效的审计范围。"
    window.close()


def test_start_scan_requires_boundary_and_scope_consent_before_callbacks(
    qapp, monkeypatch, tmp_path
):
    root = tmp_path / "current-root"
    root.mkdir()
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(root),
    )
    callbacks = []

    def forbidden(name):
        def callback(*args, **kwargs):
            callbacks.append(name)
            raise AssertionError(name)

        return callback

    window = create_window()
    window.folder_button.click()
    window.scope_consent_checkbox.setChecked(True)
    monkeypatch.setattr(app_module, "QThread", forbidden("thread"))
    monkeypatch.setattr(app_module, "AuditWorker", forbidden("worker"))
    monkeypatch.setattr(app_module, "discover_files", forbidden("discovery"))

    window._start_scan()

    assert callbacks == []
    assert not window.supported_data_checkbox.isChecked()
    assert not window.scope_consent_checkbox.isChecked()
    assert window._scope_consent is None
    assert not window.is_scanning
    assert not window.scan_button.isEnabled()
    window.close()


def test_clipboard_callback_requires_boundary_and_action_confirmation(
    qapp, monkeypatch, tmp_path
):
    reads = []
    audits = []
    questions = []

    def supplier():
        reads.append("read")
        return "synthetic clipboard"

    def audit(reader, **_kwargs):
        audits.append("audit")
        assert reader() == "synthetic clipboard"
        return SimpleNamespace(findings=(), scanned=True)

    def question(*args, **kwargs):
        questions.append(args[2])
        return question.answer

    question.answer = QMessageBox.StandardButton.No
    monkeypatch.setattr(QMessageBox, "question", question)
    monkeypatch.setattr(app_module, "audit_clipboard_once", audit)
    monkeypatch.setattr(
        app_module.QApplication,
        "clipboard",
        staticmethod(lambda: SimpleNamespace(text=supplier)),
    )
    window = create_window()

    window._scan_clipboard_once()
    assert reads == []
    assert audits == []
    assert questions == []

    window.supported_data_checkbox.setChecked(True)
    window._scan_clipboard_once()
    assert reads == []
    assert audits == []
    assert questions == []

    window._set_scope_roots((tmp_path / "ordinary-project",), status="ready")
    window.supported_data_checkbox.setChecked(True)
    window._scan_clipboard_once()
    assert reads == []
    assert audits == []
    assert questions == []

    window.scope_consent_checkbox.setChecked(True)
    stale_preview = app_module._scope_preview_for((tmp_path / "stale-project",))
    window._scope_consent = app_module.bind_scope_consent(stale_preview)
    window._scan_clipboard_once()
    assert reads == []
    assert audits == []
    assert questions == []

    window.scope_consent_checkbox.setChecked(False)
    window.scope_consent_checkbox.setChecked(True)
    window._scan_clipboard_once()
    assert reads == []
    assert audits == []
    assert len(questions) == 1

    question.answer = QMessageBox.StandardButton.Yes
    window._scan_clipboard_once()

    assert reads == ["read"]
    assert audits == ["audit"]
    assert len(questions) == 2
    assert "剪贴板" in questions[-1]
    assert "医疗" in questions[-1]
    assert "不受监管" in questions[-1]
    window.close()


def test_browser_callback_requires_boundary_and_metadata_confirmation(
    qapp, monkeypatch, tmp_path
):
    audits = []
    dialogs = []
    questions = []

    def question(*args, **kwargs):
        questions.append(args[2])
        return question.answer

    def choose(*_args, **_kwargs):
        dialogs.append("dialog")
        return str(tmp_path / "History"), ""

    def audit(path, browser):
        audits.append((path, browser))
        return SimpleNamespace(
            counts=(("history_entries", 1), ("visit_entries", 2))
        )

    question.answer = QMessageBox.StandardButton.No
    monkeypatch.setattr(QMessageBox, "question", question)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", choose)
    monkeypatch.setattr(app_module, "audit_browser_database", audit)
    window = create_window()

    window._select_browser_database()
    assert dialogs == []
    assert audits == []
    assert questions == []

    window.supported_data_checkbox.setChecked(True)
    window._select_browser_database()
    assert dialogs == []
    assert audits == []
    assert questions == []

    window._set_scope_roots((tmp_path / "ordinary-project",), status="ready")
    window.supported_data_checkbox.setChecked(True)
    window._select_browser_database()
    assert dialogs == []
    assert audits == []
    assert questions == []

    window.scope_consent_checkbox.setChecked(True)
    stale_preview = app_module._scope_preview_for((tmp_path / "stale-project",))
    window._scope_consent = app_module.bind_scope_consent(stale_preview)
    window._select_browser_database()
    assert dialogs == []
    assert audits == []
    assert questions == []

    window.scope_consent_checkbox.setChecked(False)
    window.scope_consent_checkbox.setChecked(True)
    window._select_browser_database()
    assert dialogs == []
    assert audits == []
    assert len(questions) == 1

    question.answer = QMessageBox.StandardButton.Yes
    window._select_browser_database()

    assert dialogs == ["dialog"]
    assert len(audits) == 1
    assert len(questions) == 2
    assert "元数据" in questions[-1]
    assert "医疗" in questions[-1]
    assert "不受监管" in questions[-1]
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
        _run_audit((unc_root,), disposition_key=DISPOSITION_KEY)


def test_folder_selection_rejects_unc_root(qapp, monkeypatch):
    window = create_window()
    window._comparison_state = object()
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
    assert window._comparison_state is None
    window.close()


@pytest.mark.parametrize("consent_kind", ("missing", "stale", "forged"))
def test_start_scan_rejects_missing_stale_or_forged_consent_before_side_effects(
    qapp,
    monkeypatch,
    tmp_path,
    consent_kind,
):
    root = tmp_path / "current-root"
    other = tmp_path / "other-root"
    root.mkdir()
    other.mkdir()
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(root),
    )
    window = create_window()
    window.folder_button.click()
    current_preview = window._scope_preview

    window.scope_consent_checkbox.blockSignals(True)
    window.scope_consent_checkbox.setChecked(True)
    window.scope_consent_checkbox.blockSignals(False)
    if consent_kind == "missing":
        window._scope_consent = None
    elif consent_kind == "stale":
        window._scope_consent = app_module.bind_scope_consent(current_preview)
        window._roots = (other,)
        window._update_scan_enabled()
        assert not window.scan_button.isEnabled()
    else:
        window._scope_consent = object()
        window._scope_preview = object()

    callbacks = []

    def forbidden(name):
        def callback(*args, **kwargs):
            callbacks.append(name)
            raise AssertionError(name)

        return callback

    monkeypatch.setattr(app_module, "QThread", forbidden("thread"))
    monkeypatch.setattr(app_module, "AuditWorker", forbidden("worker"))
    monkeypatch.setattr(app_module, "discover_files", forbidden("discovery"))
    monkeypatch.setattr(app_module.secrets, "token_bytes", forbidden("randomness"))

    window._start_scan()

    assert callbacks == []
    assert not window.is_scanning
    assert not window.scan_button.isEnabled()
    assert window.status_label.text() == "请重新核对并同意当前审计范围。"
    window.close()


def test_start_scan_consumes_valid_consent_before_worker_construction(
    qapp, monkeypatch, tmp_path
):
    marker = "synthetic-private-worker-marker"
    root = tmp_path / "current-root"
    root.mkdir()
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(root),
    )
    observed = []
    window = create_window()
    window.folder_button.click()
    _approve_current_scope(window)
    window._comparison_state = object()

    def exploding_worker(*args, **kwargs):
        observed.append(
            (
                window._scope_consent,
                window.scope_consent_checkbox.isChecked(),
                window.scan_button.isEnabled(),
                window._comparison_state,
            )
        )
        raise RuntimeError(marker)

    monkeypatch.setattr(app_module, "AuditWorker", exploding_worker)

    window._start_scan()

    assert observed == [(None, False, False, None)]
    assert not window.is_scanning
    assert window._thread is None
    assert window._worker is None
    assert not window.scan_button.isEnabled()
    assert marker not in window.status_label.text()
    assert window.status_label.text() == "审计失败。"
    window.close()


def test_start_scan_rejects_consent_after_selector_contract_replacement(
    qapp, monkeypatch, tmp_path
):
    root = tmp_path / "current-root"
    root.mkdir()
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(root),
    )
    callbacks = []

    def forbidden(name):
        def callback(*args, **kwargs):
            callbacks.append(name)
            raise AssertionError(name)

        return callback

    window = create_window()
    window.folder_button.click()
    _approve_current_scope(window)
    original_preview = window._scope_preview
    original_consent = window._scope_consent
    monkeypatch.setattr(app_module, "SUPPORTED_SUFFIXES", (".json",))
    monkeypatch.setattr(app_module, "QThread", forbidden("thread"))
    monkeypatch.setattr(app_module, "AuditWorker", forbidden("worker"))
    monkeypatch.setattr(app_module, "discover_files", forbidden("discovery"))
    monkeypatch.setattr(app_module.secrets, "token_bytes", forbidden("randomness"))

    window._start_scan()

    assert original_preview.selectors != app_module.SUPPORTED_SUFFIXES
    assert original_consent is not None
    assert callbacks == []
    assert window._scope_consent is None
    assert not window.scope_consent_checkbox.isChecked()
    assert not window.is_scanning
    assert not window.scan_button.isEnabled()
    assert window.status_label.text() == "请重新核对并同意当前审计范围。"
    window.close()


def test_discovery_uses_the_exact_selector_tuple_from_the_accepted_preview(
    qapp, monkeypatch, tmp_path
):
    root = tmp_path / "current-root"
    root.mkdir()
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *args, **kwargs: str(root),
    )
    captured = {}

    def discover(roots, selectors, *, max_files, max_entries):
        captured.update(
            roots=tuple(roots),
            selectors=selectors,
            max_files=max_files,
            max_entries=max_entries,
        )
        return _discovery_result(())

    monkeypatch.setattr(app_module, "discover_files", discover)
    window = create_window()
    window.folder_button.click()
    _approve_current_scope(window)
    accepted_preview = window._scope_preview

    app_module._run_audit(
        (root,),
        scope_preview=accepted_preview,
        disposition_key=DISPOSITION_KEY,
    )

    assert type(app_module.SUPPORTED_SUFFIXES) is tuple
    assert accepted_preview.selectors is app_module.SUPPORTED_SUFFIXES
    assert captured == {
        "roots": (root,),
        "selectors": accepted_preview.selectors,
        "max_files": accepted_preview.max_files,
        "max_entries": accepted_preview.max_entries,
    }
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
    outcome = _run_audit(
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
    _approve_current_scope(window)
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

    assert not window.scope_consent_checkbox.isChecked()
    assert window._scope_consent is None
    assert not window.scan_button.isEnabled()
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
    _approve_current_scope(window)
    assert window.scan_button.isEnabled()
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
    _approve_current_scope(window)
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


@pytest.mark.parametrize(
    ("coverage", "limits", "state_label", "reason", "completion"),
    (
        (1.0, (), "已完成", None, "已完成配置范围扫描。"),
        (
            0.5,
            ("file_scan_limited",),
            "覆盖受限",
            "文件扫描受限",
            "本次结果不能证明系统、账户、提供商或端点安全。",
        ),
        (
            0.0,
            ("no_supported_files",),
            "无支持文件",
            "未发现支持的文件",
            "本次结果不能证明系统、账户、提供商或端点安全。",
        ),
    ),
)
def test_coverage_ui_uses_canonical_state_percentage_reasons_and_disclaimer(
    qapp,
    monkeypatch,
    coverage,
    limits,
    state_label,
    reason,
    completion,
):
    audit_score = score((), coverage=coverage, confidence=1.0, limits=limits)
    outcome = app_module.AuditOutcome(
        findings=(),
        score=audit_score,
        reviewed_score=audit_score,
        evaluated_at=EVALUATED_AT,
        rule_version="1.1.0",
        report_json=render_json(
            audit_score,
            (),
            rule_version="1.1.0",
            evaluated_at=EVALUATED_AT,
        ),
        report_html=render_html(
            audit_score,
            (),
            rule_version="1.1.0",
            evaluated_at=EVALUATED_AT,
        ),
        scanned_roots=(Path(r"C:\synthetic\scope"),),
    )
    real_classifier = app_module.classify_coverage
    classifier_calls = []

    def classify(candidate):
        classifier_calls.append(candidate)
        return real_classifier(candidate)

    monkeypatch.setattr(app_module, "classify_coverage", classify)
    window = create_window()

    window._scan_completed(outcome)

    text = window.coverage_status_label.text()
    assert classifier_calls == [audit_score]
    assert state_label in text
    assert f"覆盖率 {coverage:.0%}" in text
    assert completion in text
    if reason is None:
        assert "原因：" not in text
        assert "系统安全" not in text
        assert "账户安全" not in text
        assert "提供商安全" not in text
        assert "端点安全" not in text
    else:
        assert f"原因：{reason}" in text
    window.close()


@pytest.mark.parametrize("invalid_kind", ("unknown_limit", "contradictory"))
def test_coverage_ui_rejects_invalid_score_with_fixed_private_failure(
    qapp, invalid_kind
):
    marker = "synthetic-private-coverage-marker"
    audit_score = score((), coverage=1.0, confidence=1.0)
    if invalid_kind == "unknown_limit":
        object.__setattr__(audit_score, "limits", (marker,))
        object.__setattr__(audit_score, "incomplete", True)
    else:
        object.__setattr__(audit_score, "coverage", 0.5)
    outcome = app_module.AuditOutcome(
        findings=(),
        score=audit_score,
        reviewed_score=audit_score,
        evaluated_at=EVALUATED_AT,
        rule_version="1.1.0",
        report_json=marker,
        report_html=marker,
        scanned_roots=(Path(rf"C:\{marker}\scope"),),
    )
    window = create_window()

    window._scan_completed(outcome)

    assert window._audit_outcome is None
    assert window.report_json == ""
    assert window.report_html == ""
    assert window.status_label.text() == "审计失败。"
    assert window.coverage_status_label.text() == "覆盖状态：尚无结果。"
    visible = " ".join(
        widget.text()
        for widget in window.findChildren(QLabel)
    )
    assert marker not in visible
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

    outcome = _run_audit(
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

    outcome = _run_audit(
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

    outcome = _run_audit(
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

    outcome = _run_audit(
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

    outcome = _run_audit(
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


def test_personal_window_has_no_optional_data_sensitivity_mode(qapp):
    window = create_window()
    retired_state = "sensitive" + "_mode"

    assert not hasattr(window, retired_state + "_checkbox")
    assert not hasattr(window, "_" + retired_state)
    assert window.share_button.isEnabled() is True
    window.close()


def test_export_new_report_has_fixed_personal_signature() -> None:
    parameters = inspect.signature(export_new_report).parameters

    assert tuple(parameters) == ("path", "content", "scanned_roots")
    assert all(
        parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        and parameter.default is inspect.Parameter.empty
        for parameter in parameters.values()
    )


def test_share_verification_starts_only_after_user_click(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompts = []
    requests = []
    monkeypatch.setattr(
        app_module.QInputDialog,
        "getText",
        lambda *args: (prompts.append(args), ("https://example.test", True))[1],
    )
    monkeypatch.setattr(
        app_module,
        "verify_public_share",
        lambda url: (requests.append(url), SimpleNamespace(reachable=False))[1],
    )
    window = create_window()

    assert prompts == []
    assert requests == []

    window.share_button.click()

    assert len(prompts) == 1
    assert requests == ["https://example.test"]
    window.close()


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
                if node.attr == "clipboard":
                    parent = parents.get(node)
                    while parent and not isinstance(
                        parent, (ast.FunctionDef, ast.AsyncFunctionDef)
                    ):
                        parent = parents.get(parent)
                    assert parent is not None
                    assert parent.name == "_scan_clipboard_once"
                else:
                    assert node.attr not in {"write_bytes", "write_text"}
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
