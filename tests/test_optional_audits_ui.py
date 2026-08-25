import json
import os
import sqlite3
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog, QMessageBox

import agentguardian.app as app_module
from agentguardian.app import create_window
from agentguardian.browser_audit import BrowserKind
from agentguardian.share_verification import ShareVerificationResult


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def _chrome_history(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE urls (id INTEGER, url TEXT);
            CREATE TABLE visits (id INTEGER, url INTEGER);
            INSERT INTO urls VALUES (1, 'https://synthetic.example/private');
            INSERT INTO visits VALUES (1, 1);
            """
        )
        connection.commit()


def _approve_personal_scope(window, root: Path) -> None:
    window._set_scope_roots((root,), status="ready")
    window.supported_data_checkbox.setChecked(True)
    window.scope_consent_checkbox.setChecked(True)
    assert window._personal_scope_ready()


def test_browser_audit_is_user_triggered_and_does_not_expose_path(
    qapp, monkeypatch, tmp_path: Path
):
    database = tmp_path / "History"
    _chrome_history(database)
    window = create_window()
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *args, **kwargs: (str(database), "Chrome History"),
    )
    monkeypatch.setattr(
        app_module.QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    window.browser_kind_combo.setCurrentIndex(
        window.browser_kind_combo.findData(BrowserKind.CHROME)
    )

    _approve_personal_scope(window, tmp_path / "ordinary-project")
    window.browser_button.click()

    assert "浏览器元数据审计完成" in window.status_label.text()
    assert str(database) not in window.status_label.text()
    assert "1" in window.status_label.text()
    window.close()


def test_clipboard_audit_is_explicit_and_keeps_report_masked(
    qapp, monkeypatch, tmp_path
):
    raw_secret = "sk-proj-synthetic-clipboard-ui-secret-123456"

    class Clipboard:
        def text(self):
            return raw_secret

    monkeypatch.setattr(
        app_module.QApplication,
        "clipboard",
        staticmethod(lambda: Clipboard()),
    )
    monkeypatch.setattr(
        app_module.QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    window = create_window()

    _approve_personal_scope(window, tmp_path / "ordinary-project")
    window.clipboard_button.click()

    payload = json.loads(window.report_json)
    assert (
        payload["supported_use_boundary"]
        == "personal_non_regulated_configuration"
    )
    assert payload["findings"]
    assert raw_secret not in window.report_json
    assert raw_secret not in window.report_html
    assert "剪贴板" in window.status_label.text()
    window.close()


def test_clipboard_audit_cancel_does_not_read_clipboard(qapp, monkeypatch, tmp_path):
    monkeypatch.setattr(
        app_module.QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.No,
    )

    def forbidden_clipboard_read():
        raise AssertionError("clipboard read must not start after cancellation")

    monkeypatch.setattr(
        app_module.QApplication,
        "clipboard",
        staticmethod(forbidden_clipboard_read),
    )
    window = create_window()

    _approve_personal_scope(window, tmp_path / "ordinary-project")
    window.clipboard_button.click()

    assert "Clipboard audit cancelled" in window.status_label.text()
    window.close()


def test_share_verification_is_explicit_and_does_not_show_pasted_url(qapp, monkeypatch):
    pasted_url = "https://public.example/share?token=synthetic-private"
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        lambda *args, **kwargs: (pasted_url, True),
    )
    monkeypatch.setattr(
        app_module.QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(
        app_module,
        "verify_public_share",
        lambda url: ShareVerificationResult(
            address="https://public.example",
            reachable=True,
            status_code=200,
            content_type="text/plain",
            bytes_read=12,
            redirects_followed=0,
            scanned_data_sent=False,
            credentials_sent=False,
            raw_response_retained=False,
            limits=(),
        ),
    )
    window = create_window()

    window.share_button.click()

    assert "联网分享验证完成" in window.status_label.text()
    assert pasted_url not in window.status_label.text()
    assert "https://public.example" in window.status_label.text()
    window.close()
