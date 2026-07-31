import json
import os
import secrets
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from .detectors import MAX_FILE_BYTES, detect_file, detect_mcp_config, load_rules
from .discovery import discover_files
from .domain import Finding, Score, Severity
from .guidance import guidance_for
from .reporting import render_html, render_json
from .scoring import score

COLOR_TOKENS = {
    "obsidian": "#0F1215",
    "surface": "#171C20",
    "border": "#394149",
    "cloud": "#F4F6F7",
    "trust": "#21C786",
    "muted": "#AAB4BB",
    "warning": "#F0BD5C",
    "critical": "#EF7167",
}
SUPPORTED_SUFFIXES = {".json", ".txt", ".md", ".log", ".yaml", ".yml"}
MAX_AUDIT_FINDINGS = 2000
MAX_AUDIT_EVIDENCE = 4000
MAX_AUDIT_FILES = 10_000
MAX_AUDIT_BYTES = 512 * 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)


@dataclass(frozen=True, slots=True)
class AuditOutcome:
    findings: tuple[Finding, ...]
    score: Score
    report_json: str
    report_html: str
    scanned_roots: tuple[Path, ...]


def export_new_report(
    path: str | Path,
    content: str,
    scanned_roots: Iterable[str | Path],
) -> None:
    """Create a report assuming a stable destination directory during open.

    Founder Alpha does not provide a handle sandbox against an active local
    reparse replacement race between the final resolution and exclusive open.
    """
    target = Path(path)
    if _is_reparse(target):
        raise ValueError("report destination is a reparse point")
    if not target.parent.is_dir():
        raise FileNotFoundError("parent directory does not exist")
    resolved_roots = tuple(Path(root).resolve(strict=False) for root in scanned_roots)
    resolved_parent = target.parent.resolve(strict=True)
    resolved_target = target.resolve(strict=False)
    if resolved_target.parent != resolved_parent:
        raise ValueError("report destination parent changed")
    for resolved_root in resolved_roots:
        if resolved_target == resolved_root or resolved_target.is_relative_to(
            resolved_root
        ):
            raise ValueError("report destination is inside a scanned root")

    if _is_reparse(target):
        raise ValueError("report destination is a reparse point")
    if not target.parent.is_dir():
        raise FileNotFoundError("parent directory does not exist")
    final_parent = target.parent.resolve(strict=True)
    final_target = target.resolve(strict=False)
    if final_parent != resolved_parent or final_target != resolved_target:
        raise OSError("report destination changed")
    if final_target.parent != final_parent:
        raise ValueError("report destination parent changed")
    for resolved_root in resolved_roots:
        if final_target == resolved_root or final_target.is_relative_to(resolved_root):
            raise ValueError("report destination is inside a scanned root")
    with open(final_target, "x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def _is_reparse(path: Path) -> bool:
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(path_stat.st_mode) or bool(
        getattr(path_stat, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _read_limited_json(path: Path) -> object:
    with open(path, "rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("JSON file limit exceeded")
    return json.loads(data)


def _append_finding_batch(
    aggregate: list[Finding],
    seen: set[Finding],
    batch: Iterable[Finding],
    evidence_count: int,
) -> tuple[int, bool]:
    for finding in batch:
        if finding in seen:
            continue
        next_evidence_count = evidence_count + len(finding.evidence)
        if (
            len(aggregate) >= MAX_AUDIT_FINDINGS
            or next_evidence_count > MAX_AUDIT_EVIDENCE
        ):
            return evidence_count, False
        aggregate.append(finding)
        seen.add(finding)
        evidence_count = next_evidence_count
    return evidence_count, True


def _run_audit(roots: tuple[Path, ...]) -> AuditOutcome:
    scan_key = secrets.token_bytes(32)
    discovered = discover_files(
        list(roots), SUPPORTED_SUFFIXES, max_files=MAX_AUDIT_FILES + 1
    )
    files = discovered[:MAX_AUDIT_FILES]
    findings: list[Finding] = []
    seen_findings: set[Finding] = set()
    limits = ["file_limit_reached"] if len(discovered) > MAX_AUDIT_FILES else []
    scanned = 0
    scanned_bytes = 0
    evidence_count = 0

    for path in files:
        try:
            file_bytes = path.stat().st_size
        except OSError:
            limits.append("file_scan_limited")
            continue
        if scanned_bytes + file_bytes > MAX_AUDIT_BYTES:
            limits.append("byte_limit_reached")
            break
        scanned_bytes += file_bytes
        try:
            result = detect_file(path, scan_key=scan_key)
        except Exception:  # noqa: BLE001 - never expose scan exception text
            limits.append("file_scan_limited")
            continue
        evidence_count, batch_complete = _append_finding_batch(
            findings, seen_findings, result.findings, evidence_count
        )
        if not batch_complete:
            limits.append("finding_limit_reached")
            break
        limits.extend(result.limits)
        if "finding_limit_reached" in result.limits:
            break
        if not result.scanned:
            continue
        if path.suffix.lower() == ".json" and result.scanned:
            try:
                config = _read_limited_json(path)
                mcp_findings = detect_mcp_config(config, path.name, scan_key=scan_key)
            except Exception:  # noqa: BLE001 - never expose parser exception text
                limits.append("mcp_config_scan_limited")
                continue
            evidence_count, batch_complete = _append_finding_batch(
                findings, seen_findings, mcp_findings, evidence_count
            )
            if not batch_complete:
                limits.append("finding_limit_reached")
                break
        scanned += 1

    if discovered:
        coverage = scanned / len(discovered)
    else:
        coverage = 0.0
        limits.append("no_supported_files")
    unique_limits = tuple(dict.fromkeys(limits))
    audit_score = score(findings, coverage=coverage, limits=unique_limits)
    rule_version = load_rules().version
    frozen_findings = tuple(findings)
    return AuditOutcome(
        findings=frozen_findings,
        score=audit_score,
        report_json=render_json(
            audit_score, frozen_findings, rule_version=rule_version
        ),
        report_html=render_html(
            audit_score, frozen_findings, rule_version=rule_version
        ),
        scanned_roots=roots,
    )


class AuditWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, roots: tuple[Path, ...]) -> None:
        super().__init__()
        self._roots = roots

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(_run_audit(self._roots))
        except Exception:  # noqa: BLE001 - fixed worker failure boundary
            self.failed.emit("scan_failed")


class AgentGuardianWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AgentGuardian")
        self.setMinimumSize(960, 640)
        self._roots: tuple[Path, ...] = ()
        self._report_roots: tuple[Path, ...] = ()
        self._thread: QThread | None = None
        self._worker: AuditWorker | None = None
        self._row_findings: list[Finding] = []
        self.is_scanning = False
        self.report_json = ""
        self.report_html = ""
        self._build_ui()
        self.setStyleSheet(_stylesheet())

    def _build_ui(self) -> None:
        central = QWidget()
        shell = QHBoxLayout(central)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        self.setCentralWidget(central)

        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(188)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(12, 14, 12, 14)
        sidebar_layout.setSpacing(6)
        brand = QLabel("AG  AgentGuardian")
        brand.setObjectName("brand")
        sidebar_layout.addWidget(brand)

        self.navigation_buttons: list[QPushButton] = []
        for index, text in enumerate(("审计范围", "风险发现", "审计报告")):
            button = QPushButton(text)
            button.setObjectName("navigation")
            button.setCheckable(True)
            button.setMinimumHeight(36)
            button.clicked.connect(
                lambda checked=False, page=index: self._switch_view(page)
            )
            sidebar_layout.addWidget(button)
            self.navigation_buttons.append(button)
        sidebar_layout.addStretch()
        shell.addWidget(self.sidebar)

        self.content_panel = QFrame()
        content_layout = QVBoxLayout(self.content_panel)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        shell.addWidget(self.content_panel, 1)

        self.trust_strip = QFrame()
        self.trust_strip.setObjectName("trustStrip")
        self.trust_strip.setFixedHeight(42)
        trust_layout = QHBoxLayout(self.trust_strip)
        trust_layout.setContentsMargins(20, 0, 20, 0)
        trust_layout.setSpacing(18)
        self.local_mode_label = QLabel("本地模式")
        self.local_mode_label.setObjectName("localMode")
        rule_version = load_rules().version
        self.trust_labels = [
            self.local_mode_label,
            QLabel("网络能力：无"),
            QLabel(f"规则版本：{rule_version}"),
            QLabel("Founder Alpha"),
        ]
        for label in self.trust_labels:
            trust_layout.addWidget(label)
        trust_layout.addStretch()
        content_layout.addWidget(self.trust_strip)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._scope_page())
        self.stack.addWidget(self._findings_page())
        self.stack.addWidget(self._report_page())
        content_layout.addWidget(self.stack, 1)
        self._switch_view(0)

    def _scope_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(12)
        layout.addWidget(_heading("审计范围"))
        layout.addWidget(QLabel("所选根目录"))
        self.root_display_label = QLabel("尚未选择")
        self.root_display_label.setObjectName("rootDisplay")
        self.root_display_label.setMinimumHeight(38)
        layout.addWidget(self.root_display_label)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.folder_button = QPushButton("选择文件夹")
        self.folder_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon)
        )
        self.folder_button.clicked.connect(self._select_folder)
        self.scan_button = QPushButton("开始审计")
        self.scan_button.setObjectName("primaryAction")
        self.scan_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
        )
        self.scan_button.setToolTip("对所选文件夹执行只读本地审计")
        self.scan_button.setEnabled(False)
        self.scan_button.clicked.connect(self._start_scan)
        actions.addWidget(self.folder_button)
        actions.addWidget(self.scan_button)
        actions.addStretch()
        layout.addLayout(actions)

        self.status_label = QLabel("请选择审计文件夹。")
        self.status_label.setObjectName("status")
        layout.addWidget(self.status_label)
        layout.addStretch()
        return page

    def _findings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(10)
        layout.addWidget(_heading("风险发现"))
        self.findings_table = QTableWidget(0, 4)
        self.findings_table.setHorizontalHeaderLabels(
            ["严重性", "规则", "来源", "已掩码证据"]
        )
        self.findings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.findings_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.findings_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.findings_table.verticalHeader().setVisible(False)
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.findings_table.itemSelectionChanged.connect(self._show_guidance)
        layout.addWidget(self.findings_table, 1)
        layout.addWidget(QLabel("人工修复步骤"))
        self.guidance_browser = QTextBrowser()
        self.guidance_browser.setMinimumHeight(120)
        self.guidance_browser.setMaximumHeight(170)
        self.guidance_browser.setPlainText("选择一项风险以查看人工步骤。")
        layout.addWidget(self.guidance_browser)
        return page

    def _report_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(10)
        layout.addWidget(_heading("审计报告"))
        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.report_mode_combo = QComboBox()
        self.report_mode_combo.addItems(["HTML", "JSON"])
        self.report_mode_combo.currentTextChanged.connect(self._refresh_report)
        self.review_button = QPushButton("审阅修复方案")
        self.review_button.clicked.connect(self._review_guidance)
        self.save_button = QPushButton("保存报告")
        self.save_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        )
        self.save_button.setToolTip("导出一份新的审计报告")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self._export_report)
        controls.addWidget(self.report_mode_combo)
        controls.addStretch()
        controls.addWidget(self.review_button)
        controls.addWidget(self.save_button)
        layout.addLayout(controls)
        self.report_browser = QTextBrowser()
        self.report_browser.setHtml("<p>尚无审计报告。</p>")
        layout.addWidget(self.report_browser, 1)
        return page

    def _switch_view(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for button_index, button in enumerate(self.navigation_buttons):
            button.setChecked(button_index == index)

    def _select_folder(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "选择审计文件夹")
        if not selected:
            return
        root = Path(selected)
        self._invalidate_report()
        self._roots = (root,)
        self.root_display_label.setText(root.name or "所选文件夹")
        self.scan_button.setEnabled(True)
        self.status_label.setText("已选择审计范围。")

    def _start_scan(self) -> None:
        if not self._roots or self.is_scanning:
            return
        self.is_scanning = True
        self.scan_button.setEnabled(False)
        self.folder_button.setEnabled(False)
        self.scan_button.setText("审计中...")
        self.status_label.setText("正在执行只读本地审计。")
        self._invalidate_report()
        self.guidance_browser.setPlainText("等待审计结果。")

        self._thread = QThread(self)
        self._worker = AuditWorker(self._roots)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.completed.connect(self._scan_completed)
        self._worker.failed.connect(self._scan_failed)
        self._worker.completed.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._worker.completed.connect(self._worker.deleteLater)
        self._worker.failed.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._thread_finished)
        self._thread.start()

    @Slot(object)
    def _scan_completed(self, outcome: AuditOutcome) -> None:
        self.report_json = outcome.report_json
        self.report_html = outcome.report_html
        self._report_roots = outcome.scanned_roots
        self._populate_findings(outcome.findings)
        self._refresh_report()
        self.save_button.setEnabled(True)
        if outcome.score.incomplete:
            coverage = f"{outcome.score.coverage:.0%}"
            finding_summary = (
                f"发现 {len(outcome.findings)} 项风险"
                if outcome.findings
                else "未发现风险"
            )
            self.status_label.setText(
                f"审计未完整：{finding_summary}，覆盖率 {coverage}；不能判定为安全。"
            )
        elif outcome.findings:
            self.status_label.setText(
                f"审计完成：发现 {len(outcome.findings)} 项风险。"
            )
        else:
            self.status_label.setText("审计完成：未发现风险。")

    @Slot(str)
    def _scan_failed(self, _code: str) -> None:
        self._invalidate_report()
        self.status_label.setText("审计失败。")
        self.guidance_browser.setPlainText("无法生成修复步骤。")

    def _invalidate_report(self) -> None:
        self.report_json = ""
        self.report_html = ""
        self._report_roots = ()
        self.findings_table.setRowCount(0)
        self._row_findings.clear()
        self.guidance_browser.setPlainText("选择一项风险以查看人工步骤。")
        self.save_button.setEnabled(False)
        self._refresh_report()

    @Slot()
    def _thread_finished(self) -> None:
        self.is_scanning = False
        self.scan_button.setText("开始审计")
        self.scan_button.setEnabled(bool(self._roots))
        self.folder_button.setEnabled(True)
        self._thread = None
        self._worker = None

    def _populate_findings(self, findings: tuple[Finding, ...]) -> None:
        rows = sum(len(finding.evidence) for finding in findings)
        self.findings_table.setRowCount(rows)
        self._row_findings.clear()
        row = 0
        for finding in findings:
            for evidence in finding.evidence:
                values = (
                    finding.severity.value,
                    finding.rule_id,
                    evidence.source,
                    evidence.masked,
                )
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if finding.severity is Severity.CRITICAL:
                        item.setForeground(QColor(COLOR_TOKENS["critical"]))
                    elif finding.severity in {Severity.HIGH, Severity.MEDIUM}:
                        item.setForeground(QColor(COLOR_TOKENS["warning"]))
                    self.findings_table.setItem(row, column, item)
                self._row_findings.append(finding)
                row += 1

    def _show_guidance(self) -> None:
        row = self.findings_table.currentRow()
        if not 0 <= row < len(self._row_findings):
            self.guidance_browser.setPlainText("选择一项风险以查看人工步骤。")
            return
        finding = self._row_findings[row]
        try:
            plan = guidance_for(finding.rule_id, finding.root_fingerprint)
        except (TypeError, ValueError):
            self.guidance_browser.setPlainText("无法生成修复步骤。")
            return
        lines = [
            *(f"{index}. {step}" for index, step in enumerate(plan.steps, 1)),
            "",
            "验证：",
            *plan.verification_steps,
        ]
        self.guidance_browser.setPlainText("\n".join(lines))

    def _review_guidance(self) -> None:
        self._switch_view(1)
        if self.findings_table.rowCount() and self.findings_table.currentRow() < 0:
            self.findings_table.selectRow(0)
        self.findings_table.setFocus(Qt.FocusReason.OtherFocusReason)
        self._show_guidance()

    def _refresh_report(self) -> None:
        if self.report_mode_combo.currentText() == "JSON":
            self.report_browser.setPlainText(self.report_json or "尚无审计报告。")
        else:
            self.report_browser.setHtml(self.report_html or "<p>尚无审计报告。</p>")

    def _export_report(self) -> None:
        mode = self.report_mode_combo.currentText()
        suffix = "json" if mode == "JSON" else "html"
        path, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出新报告",
            f"agentguardian-report.{suffix}",
            f"{mode} (*.{suffix})",
        )
        if not path:
            return
        content = self.report_json if mode == "JSON" else self.report_html
        try:
            export_new_report(path, content, self._report_roots)
        except (OSError, TypeError, ValueError):
            QMessageBox.warning(self, "导出失败", "无法导出报告。")
            return
        QMessageBox.information(self, "导出完成", "报告已导出。")

    def closeEvent(self, event) -> None:
        if self._thread is not None and self._thread.isRunning():
            self.status_label.setText("审计仍在进行，请等待完成。")
            event.ignore()
            return
        super().closeEvent(event)


def _heading(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("heading")
    return label


def _stylesheet() -> str:
    return f"""
        QMainWindow, QWidget {{
            background: {COLOR_TOKENS["obsidian"]};
            color: {COLOR_TOKENS["cloud"]};
            font-family: "Segoe UI", "Noto Sans SC";
            font-size: 13px;
            letter-spacing: 0px;
        }}
        QFrame#sidebar {{
            background: {COLOR_TOKENS["surface"]};
            border-right: 1px solid {COLOR_TOKENS["border"]};
        }}
        QLabel#brand {{
            color: {COLOR_TOKENS["cloud"]};
            font-size: 15px;
            font-weight: 600;
            padding: 5px 4px 12px 4px;
        }}
        QPushButton {{
            background: {COLOR_TOKENS["surface"]};
            border: 1px solid {COLOR_TOKENS["border"]};
            border-radius: 4px;
            color: {COLOR_TOKENS["cloud"]};
            min-height: 30px;
            padding: 3px 10px;
        }}
        QPushButton:hover {{ border-color: {COLOR_TOKENS["muted"]}; }}
        QPushButton:disabled {{ color: {COLOR_TOKENS["muted"]}; }}
        QPushButton#navigation {{
            border: 0;
            border-radius: 4px;
            text-align: left;
            padding-left: 10px;
        }}
        QPushButton#navigation:checked {{
            background: {COLOR_TOKENS["border"]};
            color: {COLOR_TOKENS["cloud"]};
        }}
        QPushButton#primaryAction {{
            background: {COLOR_TOKENS["trust"]};
            border-color: {COLOR_TOKENS["trust"]};
            color: {COLOR_TOKENS["obsidian"]};
            font-weight: 600;
        }}
        QFrame#trustStrip {{
            background: {COLOR_TOKENS["surface"]};
            border-bottom: 1px solid {COLOR_TOKENS["border"]};
        }}
        QFrame#trustStrip QLabel {{ color: {COLOR_TOKENS["muted"]}; }}
        QLabel#localMode {{ color: {COLOR_TOKENS["trust"]}; font-weight: 600; }}
        QLabel#heading {{ font-size: 20px; font-weight: 600; }}
        QLabel#rootDisplay, QLabel#status {{
            background: {COLOR_TOKENS["surface"]};
            border: 1px solid {COLOR_TOKENS["border"]};
            border-radius: 6px;
            color: {COLOR_TOKENS["muted"]};
            padding: 8px 10px;
        }}
        QTableWidget, QTextBrowser, QComboBox {{
            background: {COLOR_TOKENS["surface"]};
            border: 1px solid {COLOR_TOKENS["border"]};
            border-radius: 4px;
            color: {COLOR_TOKENS["cloud"]};
            selection-background-color: {COLOR_TOKENS["border"]};
        }}
        QTableWidget::item {{ padding: 5px; }}
        QHeaderView::section {{
            background: {COLOR_TOKENS["surface"]};
            border: 0;
            border-bottom: 1px solid {COLOR_TOKENS["border"]};
            color: {COLOR_TOKENS["muted"]};
            padding: 6px;
        }}
        QComboBox {{ min-width: 92px; padding: 4px 8px; }}
        QComboBox QAbstractItemView {{
            background: {COLOR_TOKENS["surface"]};
            color: {COLOR_TOKENS["cloud"]};
            selection-background-color: {COLOR_TOKENS["border"]};
        }}
    """


def create_window() -> AgentGuardianWindow:
    return AgentGuardianWindow()


def main() -> int:
    application = QApplication.instance() or QApplication(sys.argv)
    window = create_window()
    window.show()
    return application.exec()
