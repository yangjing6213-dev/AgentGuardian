import hashlib
from pathlib import Path

import pytest

from agentguardian.remediation import (
    ACTION_REPLACE_FIXED_FILE,
    RemediationStatus,
    apply_fixed_replacement,
    apply_openai_base_url_replacement,
    build_openai_base_url_replacement,
    preview_openai_base_url_replacement,
    preview_fixed_replacement,
    rollback_fixed_replacement,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_preview_is_dry_run_and_returns_no_path_or_raw_data(tmp_path: Path) -> None:
    target = tmp_path / "settings.toml"
    original = b"provider = 'manual'\n"
    replacement = b"provider = 'manual'\napi_access = false\n"
    target.write_bytes(original)

    preview = preview_fixed_replacement(
        target,
        expected_sha256=_sha256(original),
        replacement=replacement,
    )

    assert preview.action_id == ACTION_REPLACE_FIXED_FILE
    assert preview.status is RemediationStatus.DRY_RUN
    assert preview.target_name == target.name
    assert preview.target_sha256 == _sha256(original)
    assert preview.replacement_sha256 == _sha256(replacement)
    assert preview.backup_name == f"{target.name}.agentguardian.bak"
    assert preview.limits == ()
    assert target.read_bytes() == original
    assert not target.with_name(preview.backup_name).exists()


def test_apply_requires_confirmation_and_rechecks_hash(tmp_path: Path) -> None:
    target = tmp_path / "settings.toml"
    original = b"provider = 'manual'\n"
    replacement = b"provider = 'manual'\napi_access = false\n"
    target.write_bytes(original)

    not_confirmed = apply_fixed_replacement(
        target,
        expected_sha256=_sha256(original),
        replacement=replacement,
        confirmed=False,
    )
    assert not_confirmed.status is RemediationStatus.NOT_PERFORMED
    assert target.read_bytes() == original

    target.write_bytes(b"changed before confirmation\n")
    stale = apply_fixed_replacement(
        target,
        expected_sha256=_sha256(original),
        replacement=replacement,
        confirmed=True,
    )
    assert stale.status is RemediationStatus.NOT_PERFORMED
    assert "target_changed" in stale.limits
    assert target.read_bytes() == b"changed before confirmation\n"
    assert not target.with_name(f"{target.name}.agentguardian.bak").exists()


def test_apply_backs_up_and_atomically_replaces_fixed_target(tmp_path: Path) -> None:
    target = tmp_path / "settings.toml"
    original = b"provider = 'manual'\n"
    replacement = b"provider = 'manual'\napi_access = false\n"
    target.write_bytes(original)

    result = apply_fixed_replacement(
        target,
        expected_sha256=_sha256(original),
        replacement=replacement,
        confirmed=True,
    )

    assert result.status is RemediationStatus.APPLIED
    assert result.target_name == target.name
    assert result.original_sha256 == _sha256(original)
    assert result.resulting_sha256 == _sha256(replacement)
    assert result.backup_name == f"{target.name}.agentguardian.bak"
    assert result.limits == ()
    assert target.read_bytes() == replacement
    assert target.with_name(result.backup_name).read_bytes() == original


def test_rollback_requires_current_replacement_and_removes_backup(tmp_path: Path) -> None:
    target = tmp_path / "settings.toml"
    original = b"provider = 'manual'\n"
    replacement = b"provider = 'manual'\napi_access = false\n"
    target.write_bytes(original)
    applied = apply_fixed_replacement(
        target,
        expected_sha256=_sha256(original),
        replacement=replacement,
        confirmed=True,
    )

    rolled_back = rollback_fixed_replacement(
        target,
        expected_replacement_sha256=applied.resulting_sha256,
    )

    assert rolled_back.status is RemediationStatus.ROLLED_BACK
    assert target.read_bytes() == original
    assert not target.with_name(applied.backup_name).exists()


def test_rollback_rejects_changed_target_without_touching_backup(tmp_path: Path) -> None:
    target = tmp_path / "settings.toml"
    original = b"provider = 'manual'\n"
    replacement = b"provider = 'manual'\napi_access = false\n"
    target.write_bytes(original)
    applied = apply_fixed_replacement(
        target,
        expected_sha256=_sha256(original),
        replacement=replacement,
        confirmed=True,
    )
    target.write_bytes(b"operator changed this file\n")

    result = rollback_fixed_replacement(
        target,
        expected_replacement_sha256=applied.resulting_sha256,
    )

    assert result.status is RemediationStatus.NOT_PERFORMED
    assert "target_changed" in result.limits
    assert target.read_bytes() == b"operator changed this file\n"
    assert target.with_name(applied.backup_name).read_bytes() == original


@pytest.mark.parametrize("action_id", ("", "delete_file", "run_command"))
def test_only_fixed_replacement_action_is_allowed(
    tmp_path: Path, action_id: str
) -> None:
    target = tmp_path / "settings.toml"
    target.write_bytes(b"provider = 'manual'\n")

    with pytest.raises(ValueError, match="ACTION_NOT_ALLOWED"):
        preview_fixed_replacement(
            target,
            expected_sha256=_sha256(target.read_bytes()),
            replacement=b"provider = 'manual'\n",
            action_id=action_id,
        )


def test_reparse_target_is_rejected_before_read(tmp_path: Path) -> None:
    target = tmp_path / "settings.toml"
    source = tmp_path / "real-settings.toml"
    source.write_bytes(b"provider = 'manual'\n")
    try:
        target.symlink_to(source)
    except OSError as error:
        pytest.skip(f"file symlink unavailable: {error.__class__.__name__}")

    with pytest.raises(ValueError, match="REPARSE_TARGET_REJECTED"):
        preview_fixed_replacement(
            target,
            expected_sha256=_sha256(source.read_bytes()),
            replacement=b"provider = 'manual'\napi_access = false\n",
        )


def test_openai_base_url_replacement_is_fixed_and_preserves_safe_line_shape() -> None:
    original = (
        b"# keep this comment\n"
        b"export OPENAI_BASE_URL='https://synthetic-provider.invalid/v1' # review\n"
    )

    replacement = build_openai_base_url_replacement(original)

    assert replacement == (
        b"# keep this comment\n"
        b"export OPENAI_BASE_URL='https://api.openai.com/v1' # review\n"
    )
    assert b"synthetic-provider.invalid" not in replacement


def test_openai_base_url_replacement_requires_the_allowlisted_finding() -> None:
    with pytest.raises(ValueError, match="ACTION_NOT_ALLOWED"):
        build_openai_base_url_replacement(
            b"OPENAI_BASE_URL=https://example.invalid\n",
            action_id="run_command",
        )


def test_openai_base_url_preview_and_apply_recheck_the_target(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    original = b"OPENAI_BASE_URL=https://synthetic-provider.invalid/v1\n"
    target.write_bytes(original)

    preview = preview_openai_base_url_replacement(target)
    assert preview.status is RemediationStatus.DRY_RUN
    assert preview.target_sha256 == _sha256(original)
    assert preview.replacement_sha256 == _sha256(
        b"OPENAI_BASE_URL=https://api.openai.com/v1\n"
    )
    assert target.read_bytes() == original

    target.write_bytes(b"OPENAI_BASE_URL=https://changed.invalid/v1\n")
    stale = apply_openai_base_url_replacement(
        target,
        expected_sha256=preview.target_sha256,
        confirmed=True,
    )
    assert stale.status is RemediationStatus.NOT_PERFORMED
    assert "target_changed" in stale.limits
    assert not target.with_name(stale.backup_name).exists()


def test_openai_base_url_apply_and_rollback_are_fixed_and_bounded(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    original = b"OPENAI_BASE_URL=https://synthetic-provider.invalid/v1\n"
    target.write_bytes(original)
    preview = preview_openai_base_url_replacement(target)

    applied = apply_openai_base_url_replacement(
        target,
        expected_sha256=preview.target_sha256,
        confirmed=True,
    )

    assert applied.status is RemediationStatus.APPLIED
    assert target.read_bytes() == b"OPENAI_BASE_URL=https://api.openai.com/v1\n"
    assert target.with_name(applied.backup_name).read_bytes() == original

    rolled_back = rollback_fixed_replacement(
        target,
        expected_replacement_sha256=applied.resulting_sha256,
    )
    assert rolled_back.status is RemediationStatus.ROLLED_BACK
    assert target.read_bytes() == original
