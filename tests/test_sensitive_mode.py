from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

import agentguardian.app as app_module
from agentguardian.app import create_window, export_new_report
from agentguardian.sensitive_mode import SensitiveModePolicy


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def test_sensitive_mode_is_local_only_and_requires_export_confirmation():
    policy = SensitiveModePolicy.enabled_policy()

    assert policy.enabled is True
    assert policy.api_access is False
    assert policy.raw_persistence is False
    assert policy.export_requires_confirmation is True

    with pytest.raises(PermissionError, match="SENSITIVE_EXPORT_CONFIRMATION_REQUIRED"):
        policy.validate_export(False)
    policy.validate_export(True)


def test_sensitive_mode_rejects_relaxed_security_fields():
    with pytest.raises(ValueError, match="SENSITIVE_MODE_INVALID"):
        SensitiveModePolicy(
            enabled=True,
            api_access=True,
        )


def test_sensitive_export_requires_explicit_confirmation(tmp_path: Path):
    destination = tmp_path / "report.json"
    policy = SensitiveModePolicy.enabled_policy()

    with pytest.raises(PermissionError, match="SENSITIVE_EXPORT_CONFIRMATION_REQUIRED"):
        export_new_report(
            destination,
            '{"safe": true}',
            (),
            sensitive_mode=policy,
        )

    export_new_report(
        destination,
        '{"safe": true}',
        (),
        sensitive_mode=policy,
        export_confirmed=True,
    )
    assert destination.read_text(encoding="utf-8") == '{"safe": true}'


def test_window_exposes_explicit_sensitive_mode_switch(qapp):
    window = create_window()

    assert window.sensitive_mode_checkbox.isChecked() is False
    assert window._sensitive_mode.enabled is False
    assert window.share_button.isEnabled() is True

    window.sensitive_mode_checkbox.setChecked(True)

    assert window._sensitive_mode == SensitiveModePolicy.enabled_policy()
    assert window.scope_consent_checkbox.isChecked() is False
    assert window.share_button.isEnabled() is False

    window.sensitive_mode_checkbox.setChecked(False)
    assert window.share_button.isEnabled() is True
    window.close()


def test_sensitive_mode_blocks_share_before_prompt(qapp, monkeypatch):
    window = create_window()
    window.sensitive_mode_checkbox.setChecked(True)

    monkeypatch.setattr(
        app_module.QInputDialog,
        "getText",
        lambda *_args, **_kwargs: pytest.fail("sensitive mode opened network prompt"),
    )

    window._verify_share()

    assert "禁止联网分享验证" in window.status_label.text()
    window.close()
