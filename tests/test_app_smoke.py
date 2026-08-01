import ast
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
from agentguardian.domain import Evidence, Finding, RiskDomain, Severity


@pytest.fixture(scope="session")
def qapp():
    application = QApplication.instance() or QApplication([])
    yield application


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

    outcome = app_module._run_audit((tmp_path,))

    assert outcome.score.coverage == 0.5
    assert outcome.score.incomplete is True
    assert "directory_read_limited" in outcome.score.limits


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
        "规则版本：1.0.0",
        "Founder Alpha",
    ]
    assert "映射网络盘" in window.local_mode_label.toolTip()
    assert "依赖" in window.trust_labels[1].toolTip()

    for index, button in enumerate(window.navigation_buttons):
        button.click()
        assert window.stack.currentIndex() == index

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
        app_module._run_audit((unc_root,))


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
    outcome = app_module._run_audit((report_root,))
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

    def fake_detect_file(path, *, scan_key):
        calls.append(path)
        return FileDetectionResult(batches[path], True, ())

    monkeypatch.setattr(app_module, "detect_file", fake_detect_file)

    outcome = app_module._run_audit((tmp_path,))

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

    def fake_detect_file(path, *, scan_key):
        calls.append(path)
        return FileDetectionResult(batches[path], True, ())

    monkeypatch.setattr(app_module, "detect_file", fake_detect_file)

    outcome = app_module._run_audit((tmp_path,))

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

    def fake_detect_file(path, *, scan_key):
        calls.append(path)
        return FileDetectionResult((), True, ())

    monkeypatch.setattr(app_module, "discover_files", fake_discover)
    monkeypatch.setattr(app_module, "detect_file", fake_detect_file)

    outcome = app_module._run_audit((tmp_path,))

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

    def fake_detect_file(path, *, scan_key):
        calls.append(path)
        return FileDetectionResult((), True, ())

    monkeypatch.setattr(app_module, "detect_file", fake_detect_file)

    outcome = app_module._run_audit((tmp_path,))

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
        lambda path, *, scan_key: FileDetectionResult((finding, finding), True, ()),
    )

    outcome = app_module._run_audit((tmp_path,))

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
