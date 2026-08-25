from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib

import pytest

from agentguardian import __main__ as entrypoint
from agentguardian import codex_integration
from agentguardian.codex_integration import (
    BEGIN_MARKER,
    CONFIG_LIMIT,
    END_MARKER,
    MANIFEST_RELATIVE,
    PENDING_RELATIVE,
    SKILL_RELATIVE,
    install_integration,
    uninstall_integration,
)


def test_frozen_skill_source_accepts_reviewed_bundle_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    skill = bundle / "agentguardian_skill"
    skill.mkdir(parents=True)
    expected = {
        "LICENSE": b"Apache-2.0",
        "README.md": b"readme",
        "SKILL.md": b"skill",
    }
    for name, data in expected.items():
        (skill / name).write_bytes(data)
    monkeypatch.setattr(codex_integration, "SKILL_SOURCE_ROOT", tmp_path / "missing")
    monkeypatch.setattr(codex_integration.sys, "_MEIPASS", str(bundle), raising=False)

    assert codex_integration._skill_source() == tuple(expected.items())


def _environment(root: Path) -> dict[str, str]:
    local_app_data = root / "localappdata"
    local_app_data.mkdir(parents=True, exist_ok=True)
    return {
        "USERPROFILE": str(root),
        "LOCALAPPDATA": str(local_app_data),
    }


def _state_path(root: Path, relative: Path) -> Path:
    return root / "localappdata" / relative


def _launchers(root: Path) -> Path:
    directory = root / "Programs" / "AgentGuardian Integrations Preview"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "AgentGuardian.exe").write_bytes(b"gui")
    mcp = directory / "AgentGuardianMcp.exe"
    mcp.write_bytes(b"mcp")
    return mcp


def _protect(value: bytes) -> bytes:
    return b"protected:" + value


def _unprotect(value: bytes) -> bytes:
    assert value.startswith(b"protected:")
    return value[len(b"protected:") :]


def _install_mcp(root: Path, executable: Path | None = None) -> str:
    return install_integration(
        install_skill=False,
        enable_mcp=True,
        mcp_executable=executable or _launchers(root),
        environ=_environment(root),
        protect=_protect,
    )


def test_all_task_selections_are_bounded(tmp_path: Path) -> None:
    assert install_integration(
        install_skill=False,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "INTEGRATION_INPUT_INVALID"
    assert install_integration(
        install_skill=1,  # type: ignore[arg-type]
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "INTEGRATION_INPUT_INVALID"

    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "INTEGRATION_INSTALLED"
    assert (tmp_path / SKILL_RELATIVE / "SKILL.md").is_file()

    mcp_root = tmp_path / "mcp"
    assert _install_mcp(mcp_root) == "INTEGRATION_INSTALLED"
    both_root = tmp_path / "both"
    assert install_integration(
        install_skill=True,
        enable_mcp=True,
        mcp_executable=_launchers(both_root),
        environ=_environment(both_root),
        protect=_protect,
    ) == "INTEGRATION_INSTALLED"


def test_mcp_config_has_exact_reviewed_shape(tmp_path: Path) -> None:
    executable = _launchers(tmp_path)
    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"

    config = tmp_path / ".codex" / "config.toml"
    parsed = tomllib.loads(config.read_text(encoding="utf-8"))
    server = parsed["mcp_servers"]["agentguardian"]
    assert server == {
        "command": str(executable),
        "args": ["--stdio-mcp"],
        "enabled": True,
        "enabled_tools": ["prepare_audit", "run_prepared_audit"],
        "default_tools_approval_mode": "prompt",
        "tools": {
            "prepare_audit": {"approval_mode": "auto"},
            "run_prepared_audit": {"approval_mode": "prompt"},
        },
    }


def test_unicode_config_upgrade_and_uninstall_preserve_original_bytes(
    tmp_path: Path,
) -> None:
    executable = _launchers(tmp_path)
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    original = b'[user]\nlabel = "\xe4\xb8\xad\xe6\x96\x87"\n'
    config.write_bytes(original)

    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "INTEGRATION_REMOVED"
    assert config.read_bytes() == original
    assert not (tmp_path / "localappdata" / "AgentGuardian").exists()


def test_config_limit_allows_bounded_dpapi_backup_envelope(tmp_path: Path) -> None:
    executable = _launchers(tmp_path)
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    original = b"#" + b"a" * 430000 + b"\n"
    config.write_bytes(original)

    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "INTEGRATION_REMOVED"
    assert config.read_bytes() == original


def test_foreign_config_and_duplicate_markers_are_preserved(tmp_path: Path) -> None:
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(
        "[mcp_servers.agentguardian]\ncommand = 'other'\n", encoding="utf-8"
    )
    assert _install_mcp(tmp_path) == "CODEX_CONFIG_CONFLICT"
    before = config.read_bytes()
    assert config.read_bytes() == before

    config.write_bytes(
        (BEGIN_MARKER + "\n" + END_MARKER + "\n" + BEGIN_MARKER + "\n").encode()
    )
    assert _install_mcp(tmp_path) == "CODEX_CONFIG_CONFLICT"


@pytest.mark.parametrize(
    "content",
    (
        b"[broken\n",
        b"x = '" + b"a" * CONFIG_LIMIT,
    ),
    ids=("malformed", "oversized"),
)
def test_invalid_or_oversized_config_fails_without_replacement(
    tmp_path: Path, content: bytes
) -> None:
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_bytes(content)
    before = config.read_bytes()

    result = _install_mcp(tmp_path)

    assert result in {"CODEX_CONFIG_INVALID", "CODEX_CONFIG_TOO_LARGE"}
    assert config.read_bytes() == before


@pytest.mark.parametrize(
    "name",
    ("AgentGuardian.exe", "other.exe"),
)
def test_mcp_executable_must_be_the_console_sibling(
    tmp_path: Path, name: str
) -> None:
    directory = tmp_path / "installed"
    directory.mkdir()
    (directory / "AgentGuardian.exe").write_bytes(b"gui")
    candidate = directory / name
    candidate.write_bytes(b"candidate")

    assert install_integration(
        install_skill=False,
        enable_mcp=True,
        mcp_executable=candidate,
        environ=_environment(tmp_path),
        protect=_protect,
    ) == "INTEGRATION_PATH_INVALID"


def test_dpapi_failure_and_manifest_failure_roll_back_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _launchers(tmp_path)
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_bytes(b"[user]\nvalue = 1\n")
    before = config.read_bytes()

    def fail_protect(_: bytes) -> bytes:
        raise RuntimeError("private-native-detail")

    assert install_integration(
        install_skill=False,
        enable_mcp=True,
        mcp_executable=executable,
        environ=_environment(tmp_path),
        protect=fail_protect,
    ) == "INTEGRATION_DPAPI_FAILED"
    assert config.read_bytes() == before
    assert not _state_path(tmp_path, MANIFEST_RELATIVE).exists()

    original_commit = __import__(
        "agentguardian.codex_integration", fromlist=["_commit_ownership_manifest"]
    )._commit_ownership_manifest

    def fail_manifest(_: object) -> None:
        raise RuntimeError("private-manifest-detail")

    monkeypatch.setattr(
        "agentguardian.codex_integration._commit_ownership_manifest",
        fail_manifest,
    )
    assert install_integration(
        install_skill=False,
        enable_mcp=True,
        mcp_executable=executable,
        environ=_environment(tmp_path),
        protect=_protect,
    ) == "INTEGRATION_INSTALL_FAILED"
    assert config.read_bytes() == before
    assert not _state_path(tmp_path, MANIFEST_RELATIVE).exists()
    monkeypatch.setattr(
        "agentguardian.codex_integration._commit_ownership_manifest",
        original_commit,
    )


def test_skill_conflict_preserves_unmanaged_files(tmp_path: Path) -> None:
    skill = tmp_path / SKILL_RELATIVE
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("user-owned", encoding="utf-8")
    unknown = skill / "notes.txt"
    unknown.write_text("keep", encoding="utf-8")

    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "SKILL_CONFLICT"
    assert (skill / "SKILL.md").read_text(encoding="utf-8") == "user-owned"
    assert unknown.read_text(encoding="utf-8") == "keep"


def test_uninstall_removes_only_managed_block_and_preserves_later_edits(
    tmp_path: Path,
) -> None:
    executable = _launchers(tmp_path)
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text("[user]\nvalue = 1\n", encoding="utf-8")
    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    with config.open("ab") as stream:
        stream.write(b"\n[user_extra]\nvalue = 2\n")

    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "INTEGRATION_REMOVED"
    assert config.read_bytes() == b"[user]\r\nvalue = 1\r\n\n[user_extra]\nvalue = 2\n"
    assert not _state_path(tmp_path, MANIFEST_RELATIVE).exists()
    assert not _state_path(tmp_path, Path("AgentGuardian/codex-config-backup-v1.bin")).exists()
    assert uninstall_integration(environ=_environment(tmp_path)) == "INTEGRATION_NOT_PRESENT"


def test_missing_original_config_is_removed_after_uninstall(tmp_path: Path) -> None:
    executable = _launchers(tmp_path)
    assert install_integration(
        install_skill=False,
        enable_mcp=True,
        mcp_executable=executable,
        environ=_environment(tmp_path),
        protect=_protect,
    ) == "INTEGRATION_INSTALLED"
    config = tmp_path / ".codex" / "config.toml"
    assert config.is_file()
    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "INTEGRATION_REMOVED"
    assert not config.exists()


def test_existing_empty_config_survives_uninstall(tmp_path: Path) -> None:
    executable = _launchers(tmp_path)
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_bytes(b"")

    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "INTEGRATION_REMOVED"
    assert config.exists()
    assert config.read_bytes() == b""


def test_marker_change_blocks_uninstall_and_keeps_recovery(
    tmp_path: Path,
) -> None:
    executable = _launchers(tmp_path)
    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    config = tmp_path / ".codex" / "config.toml"
    config.write_bytes(config.read_bytes().replace(b'"--stdio-mcp"', b'"changed"'))

    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "CODEX_CONFIG_CONFLICT"
    assert _state_path(tmp_path, MANIFEST_RELATIVE).exists()
    assert _state_path(tmp_path, Path("AgentGuardian/codex-config-backup-v1.bin")).exists()


def test_missing_managed_marker_keeps_recovery_material(tmp_path: Path) -> None:
    executable = _launchers(tmp_path)
    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    config = tmp_path / ".codex" / "config.toml"
    config.write_text("[user]\nvalue = 1\n", encoding="utf-8")

    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "CODEX_CONFIG_CONFLICT"
    assert _state_path(tmp_path, MANIFEST_RELATIVE).exists()
    assert _state_path(tmp_path, Path("AgentGuardian/codex-config-backup-v1.bin")).exists()


def test_cleanup_failure_retains_encrypted_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _launchers(tmp_path)
    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    backup = _state_path(tmp_path, Path("AgentGuardian/codex-config-backup-v1.bin"))
    import agentguardian.codex_integration as integration

    original_remove = integration._remove_file

    def fail_backup(path: Path, root: Path, code: str) -> None:
        if path == backup:
            raise integration.IntegrationError("INTEGRATION_CLEANUP_REQUIRED")
        original_remove(path, root, code)

    monkeypatch.setattr(integration, "_remove_file", fail_backup)
    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "INTEGRATION_CLEANUP_REQUIRED"
    assert backup.exists()
    assert not _state_path(tmp_path, MANIFEST_RELATIVE).exists()
    pending = _state_path(tmp_path, PENDING_RELATIVE)
    assert pending.exists()

    monkeypatch.setattr(integration, "_remove_file", original_remove)
    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "INTEGRATION_REMOVED"
    assert not backup.exists()
    assert not pending.exists()


def test_uninstall_cleanup_failure_is_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _launchers(tmp_path)
    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    import agentguardian.codex_integration as integration

    manifest = _state_path(tmp_path, MANIFEST_RELATIVE)
    backup = _state_path(tmp_path, Path("AgentGuardian/codex-config-backup-v1.bin"))
    original_remove = integration._remove_file
    failed = False

    def fail_manifest_once(path: Path, root: Path, code: str) -> None:
        nonlocal failed
        if path == manifest and not failed:
            failed = True
            raise integration.IntegrationError("INTEGRATION_CLEANUP_REQUIRED")
        original_remove(path, root, code)

    monkeypatch.setattr(integration, "_remove_file", fail_manifest_once)
    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "INTEGRATION_CLEANUP_REQUIRED"
    assert backup.exists()
    assert manifest.exists()

    monkeypatch.setattr(integration, "_remove_file", original_remove)
    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "INTEGRATION_REMOVED"
    assert not backup.exists()
    assert not manifest.exists()


def test_managed_skill_upgrade_replaces_unchanged_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "INTEGRATION_INSTALLED"
    import agentguardian.codex_integration as integration

    source = tmp_path / "skill-source"
    source.mkdir()
    for name in integration.SKILL_FILES:
        (source / name).write_bytes(b"replacement-" + name.encode())
    monkeypatch.setattr(integration, "SKILL_SOURCE_ROOT", source)
    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "INTEGRATION_INSTALLED"
    assert (tmp_path / SKILL_RELATIVE / "SKILL.md").read_bytes() == b"replacement-SKILL.md"


def test_mcp_then_skill_upgrade_keeps_original_backup_hash(
    tmp_path: Path,
) -> None:
    executable = _launchers(tmp_path)
    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "INTEGRATION_INSTALLED"
    assert uninstall_integration(
        environ=_environment(tmp_path),
        unprotect=_unprotect,
    ) == "INTEGRATION_REMOVED"


def test_modified_managed_skill_blocks_upgrade_without_changes(
    tmp_path: Path,
) -> None:
    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "INTEGRATION_INSTALLED"
    skill = tmp_path / SKILL_RELATIVE
    (skill / "SKILL.md").write_text("user edit", encoding="utf-8")
    before = {path.name: path.read_bytes() for path in skill.iterdir()}

    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "SKILL_CONFLICT"
    assert {path.name: path.read_bytes() for path in skill.iterdir()} == before


def test_nonempty_unowned_skill_directory_is_not_overwritten(tmp_path: Path) -> None:
    skill = tmp_path / SKILL_RELATIVE
    skill.mkdir(parents=True)
    (skill / "notes.txt").write_text("user-owned", encoding="utf-8")

    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "SKILL_CONFLICT"
    assert not (skill / "SKILL.md").exists()


def test_skill_install_after_mcp_only_refuses_user_skill_files(tmp_path: Path) -> None:
    executable = _launchers(tmp_path)
    assert _install_mcp(tmp_path, executable) == "INTEGRATION_INSTALLED"
    skill = tmp_path / SKILL_RELATIVE
    skill.mkdir(parents=True)
    (skill / "notes.txt").write_text("user-owned", encoding="utf-8")

    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "SKILL_CONFLICT"
    assert not (skill / "SKILL.md").exists()
    assert (skill / "notes.txt").read_text(encoding="utf-8") == "user-owned"


def test_backup_discard_failure_maps_to_cleanup_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        entrypoint,
        "_frozen_launcher",
        lambda: None,
    )
    monkeypatch.setattr(
        "agentguardian.codex_integration.install_integration",
        lambda **_: "INTEGRATION_BACKUP_DISCARD_FAILED",
    )
    assert entrypoint.main(["--install-codex-integration=mcp"]) == 3


def test_reparse_and_unc_user_roots_are_rejected(tmp_path: Path) -> None:
    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ={"USERPROFILE": r"\\server\share"},
    ) == "INTEGRATION_USERPROFILE_INVALID"
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation unavailable")
    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(linked),
    ) == "INTEGRATION_USERPROFILE_INVALID"


def test_temporary_write_failure_is_fixed_and_leaves_no_integration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _launchers(tmp_path)
    import agentguardian.codex_integration as integration

    def fail_write(*_: object, **__: object) -> None:
        raise integration.IntegrationError("INTEGRATION_TEMP_WRITE_FAILED")

    monkeypatch.setattr(integration, "_atomic_write", fail_write)
    assert _install_mcp(tmp_path, executable) == "INTEGRATION_TEMP_WRITE_FAILED"
    assert not _state_path(tmp_path, MANIFEST_RELATIVE).exists()
    assert not (tmp_path / ".codex" / "config.toml").exists()


def test_managed_upgrade_success_discards_superseded_backup(tmp_path: Path) -> None:
    executable = _launchers(tmp_path)
    assert install_integration(
        install_skill=True,
        enable_mcp=True,
        mcp_executable=executable,
        environ=_environment(tmp_path),
        protect=_protect,
    ) == "INTEGRATION_INSTALLED"
    assert install_integration(
        install_skill=True,
        enable_mcp=True,
        mcp_executable=executable,
        environ=_environment(tmp_path),
        protect=_protect,
    ) == "INTEGRATION_INSTALLED"
    assert not list(_state_path(tmp_path, Path("AgentGuardian")).glob("*.superseded.*"))


def test_frozen_launcher_contracts(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setattr(entrypoint.sys, "frozen", True, raising=False)
    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\installed\AgentGuardianMcp.exe")
    assert entrypoint.main([]) == 64
    assert entrypoint.main(["--purge-protected-state"]) == 64
    assert entrypoint.main(["--stdio-mcp", "extra"]) == 64
    monkeypatch.setattr(entrypoint.sys, "executable", r"C:\installed\AgentGuardian.exe")
    fake_app = type("FakeApp", (), {"main": staticmethod(lambda: 0)})()
    monkeypatch.setitem(sys.modules, "agentguardian.app", fake_app)
    assert entrypoint.main([]) == 0
    assert entrypoint.main(["--stdio-mcp"]) == 64


def test_modified_skill_and_unknown_file_are_preserved_and_reported(
    tmp_path: Path,
) -> None:
    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "INTEGRATION_INSTALLED"
    skill = tmp_path / SKILL_RELATIVE
    (skill / "SKILL.md").write_text("user edit", encoding="utf-8")
    unknown = skill / "keep.txt"
    unknown.write_text("keep", encoding="utf-8")

    assert uninstall_integration(environ=_environment(tmp_path)) == "INTEGRATION_CLEANUP_REQUIRED"
    assert (skill / "SKILL.md").read_text(encoding="utf-8") == "user edit"
    assert unknown.read_text(encoding="utf-8") == "keep"
    assert _state_path(tmp_path, MANIFEST_RELATIVE).exists()


def test_unknown_only_skill_file_requires_manual_cleanup(
    tmp_path: Path,
) -> None:
    assert install_integration(
        install_skill=True,
        enable_mcp=False,
        environ=_environment(tmp_path),
    ) == "INTEGRATION_INSTALLED"
    skill = tmp_path / SKILL_RELATIVE
    (skill / "keep.txt").write_text("keep", encoding="utf-8")

    assert uninstall_integration(environ=_environment(tmp_path)) == (
        "INTEGRATION_CLEANUP_REQUIRED"
    )
    assert (skill / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert _state_path(tmp_path, MANIFEST_RELATIVE).exists()


def test_upgrade_backup_discard_failure_restores_prior_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _launchers(tmp_path)
    assert install_integration(
        install_skill=True,
        enable_mcp=True,
        mcp_executable=executable,
        environ=_environment(tmp_path),
        protect=_protect,
    ) == "INTEGRATION_INSTALLED"
    config = tmp_path / ".codex" / "config.toml"
    skill = tmp_path / SKILL_RELATIVE
    before = {
        "config": config.read_bytes(),
        "skill": {path.name: path.read_bytes() for path in skill.iterdir()},
        "backup": _state_path(tmp_path, Path("AgentGuardian/codex-config-backup-v1.bin")).read_bytes(),
        "manifest": _state_path(tmp_path, MANIFEST_RELATIVE).read_bytes(),
    }

    def fail_discard(_: object) -> None:
        raise __import__("agentguardian.codex_integration", fromlist=["IntegrationError"]).IntegrationError(
            "INTEGRATION_BACKUP_DISCARD_FAILED"
        )

    monkeypatch.setattr(
        "agentguardian.codex_integration._discard_superseded_backup", fail_discard
    )
    assert install_integration(
        install_skill=True,
        enable_mcp=True,
        mcp_executable=executable,
        environ=_environment(tmp_path),
        protect=_protect,
    ) == "INTEGRATION_BACKUP_DISCARD_FAILED"
    assert config.read_bytes() == before["config"]
    assert {path.name: path.read_bytes() for path in skill.iterdir()} == before["skill"]
    assert _state_path(tmp_path, Path("AgentGuardian/codex-config-backup-v1.bin")).read_bytes() == before["backup"]
    assert _state_path(tmp_path, MANIFEST_RELATIVE).read_bytes() == before["manifest"]


def test_manifest_contains_hashes_only(tmp_path: Path) -> None:
    executable = _launchers(tmp_path)
    assert install_integration(
        install_skill=True,
        enable_mcp=True,
        mcp_executable=executable,
        environ=_environment(tmp_path),
        protect=_protect,
    ) == "INTEGRATION_INSTALLED"
    manifest = _state_path(tmp_path, MANIFEST_RELATIVE).read_bytes()
    data = json.loads(manifest)
    assert data["schema"] == 1
    assert all(len(item["sha256"]) == 64 for item in data["skill_files"])
    assert hashlib.sha256(manifest).hexdigest()
    assert str(tmp_path) not in manifest.decode("utf-8")
    assert b"content_b64" not in manifest


def test_dispatch_rejects_mixed_modes_and_keeps_stdio_qt_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[str] = []
    monkeypatch.setattr(
        "agentguardian.mcp_server.run_stdio", lambda: called.append("stdio") or 0
    )
    assert entrypoint.main(["--stdio-mcp"]) == 0
    assert called == ["stdio"]
    assert entrypoint.main(["--stdio-mcp", "--purge-protected-state"]) == 64
    assert entrypoint.main(["--unknown-mode"]) == 64


def test_dispatch_maps_integration_codes_without_importing_gui(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[bool, bool]] = []
    monkeypatch.setattr(
        "agentguardian.codex_integration.install_integration",
        lambda **kwargs: seen.append(
            (kwargs["install_skill"], kwargs["enable_mcp"])
        )
        or "INTEGRATION_INSTALLED",
    )
    assert entrypoint.main(["--install-codex-integration=skill,mcp"]) == 0
    assert seen == [(True, True)]
    monkeypatch.setattr(
        "agentguardian.codex_integration.install_integration",
        lambda **_: "CODEX_CONFIG_CONFLICT",
    )
    assert entrypoint.main(["--install-codex-integration=mcp"]) == 2
