import json
import os
import sqlite3
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QFileDialog

import agentguardian.app as app_module
from agentguardian.app import create_window
from agentguardian.browser_audit import BrowserKind


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
    window.browser_kind_combo.setCurrentIndex(
        window.browser_kind_combo.findData(BrowserKind.CHROME)
    )

    window.browser_button.click()

    assert "浏览器元数据审计完成" in window.status_label.text()
    assert str(database) not in window.status_label.text()
    assert "1" in window.status_label.text()
    window.close()


def test_clipboard_audit_is_explicit_and_keeps_report_masked(qapp, monkeypatch):
    raw_secret = "sk-proj-synthetic-clipboard-ui-secret-123456"

    class Clipboard:
        def text(self):
            return raw_secret

    monkeypatch.setattr(
        app_module.QApplication,
        "clipboard",
        staticmethod(lambda: Clipboard()),
    )
    window = create_window()

    window.clipboard_button.click()

    payload = json.loads(window.report_json)
    assert payload["findings"]
    assert raw_secret not in window.report_json
    assert raw_secret not in window.report_html
    assert "剪贴板" in window.status_label.text()
    window.close()
