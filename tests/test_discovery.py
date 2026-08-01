import errno
import inspect
import os
import subprocess
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

from agentguardian import discovery
from agentguardian.discovery import discover_files, known_config_roots


def _symlink_or_skip(link: Path, target: Path, *, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        unsupported = {
            errno.EACCES,
            errno.EPERM,
            errno.ENOSYS,
            getattr(errno, "ENOTSUP", -1),
            getattr(errno, "EOPNOTSUPP", -1),
        }
        if (
            error.errno in unsupported
            or getattr(error, "winerror", None) in {50, 1314}
        ):
            pytest.skip(f"symlink creation is unavailable: {error}")
        raise


def _junction_or_skip(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode:
        output = f"{result.stdout}\n{result.stderr}".casefold()
        unavailable_markers = (
            "access is denied",
            "not supported",
            "privilege",
            "客户端没有所需的特权",
            "拒绝访问",
            "不支持",
            "需要提升",
        )
        if any(marker in output for marker in unavailable_markers):
            pytest.skip(f"junction creation is unavailable: {output.strip()}")
        pytest.fail(f"junction creation failed unexpectedly: {output.strip()}")


def test_discovery_accepts_sorted_bounded_directory_below_drive_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    for name in ("c.json", "a.JSON", "b.json"):
        (root / name).write_text("{}", encoding="utf-8")
    (root / "ignore.bin").write_bytes(b"x")
    (root / "folder.json").mkdir()

    result = discover_files([root], {".json"}, max_files=2)

    assert result.files == (root / "a.JSON", root / "b.json")
    assert result.limits == ("file_limit_reached",)


def test_discovery_bounds_all_directory_entries(tmp_path: Path) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    for index in range(5):
        (root / f"ignored-{index}.bin").write_bytes(b"x")

    result = discover_files(
        [root], {".json"}, max_files=10, max_entries=3
    )

    assert result.files == ()
    assert result.entries_seen == 3
    assert result.limits == ("entry_limit_reached",)


def test_discovery_reports_unreadable_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "selected"
    blocked = root / "blocked"
    blocked.mkdir(parents=True)
    visible = root / "visible.json"
    visible.write_text("{}", encoding="utf-8")
    real_scandir = discovery.os.scandir

    def deny_blocked(path: os.PathLike[str]):
        if Path(path) == blocked:
            raise PermissionError("synthetic denial")
        return real_scandir(path)

    monkeypatch.setattr(discovery.os, "scandir", deny_blocked)

    result = discover_files([root], {".json"})

    assert result.files == (visible,)
    assert "directory_read_limited" in result.limits


@pytest.mark.parametrize("max_files", (0, -1))
def test_discovery_requires_a_positive_limit(tmp_path: Path, max_files: int) -> None:
    with pytest.raises(ValueError, match="max_files"):
        discover_files([tmp_path], {".json"}, max_files=max_files)


def test_discovery_requires_explicit_roots() -> None:
    roots = inspect.signature(discover_files).parameters["roots"]

    assert roots.default is inspect.Parameter.empty


def test_discover_files_documents_active_attacker_limit() -> None:
    docstring = inspect.getdoc(discover_files)

    assert docstring is not None
    assert "stable snapshot" in docstring
    assert "active local attacker" in docstring


def test_entry_sort_key_breaks_casefold_ties_deterministically() -> None:
    entries = [
        SimpleNamespace(name="a.json"),
        SimpleNamespace(name="B.json"),
        SimpleNamespace(name="A.json"),
    ]

    ordered = sorted(entries, key=discovery._entry_sort_key)

    assert [entry.name for entry in ordered] == ["A.json", "a.json", "B.json"]


@pytest.mark.parametrize(
    "root",
    (
        PureWindowsPath("\\"),
        PureWindowsPath("C:/"),
        PureWindowsPath("//server/share/"),
        PureWindowsPath("//?/Volume{01234567-89AB-CDEF-0123-456789ABCDEF}/"),
    ),
    ids=("current-drive", "drive", "unc-share", "volume"),
)
def test_discovery_rejects_windows_roots_before_filesystem_access(
    root: PureWindowsPath, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_lstat(path: object) -> os.stat_result:
        raise AssertionError(f"filesystem access attempted for {path}")

    monkeypatch.setattr(discovery.os, "lstat", unexpected_lstat)

    with pytest.raises(ValueError, match="Windows root"):
        discover_files([root], {".json"})  # type: ignore[list-item]


def test_discovery_does_not_follow_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "selected"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "local.json").write_text("{}", encoding="utf-8")
    secret = outside / "secret.json"
    secret.write_text("{}", encoding="utf-8")
    _symlink_or_skip(root / "linked-directory", outside, directory=True)
    _symlink_or_skip(root / "linked-file.json", secret, directory=False)

    result = discover_files([root], {".json"})

    assert result.files == (root / "local.json",)
    assert result.limits == ("reparse_excluded",)


def test_discovery_skips_root_beneath_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    nested = outside / "nested"
    nested.mkdir(parents=True)
    (nested / "secret.json").write_text("{}", encoding="utf-8")
    link = tmp_path / "link"
    _symlink_or_skip(link, outside, directory=True)

    result = discover_files([link / "nested"], {".json"})

    assert result.files == ()
    assert result.limits == ("root_reparse_excluded",)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction test")
def test_discovery_does_not_follow_junctions(tmp_path: Path) -> None:
    root = tmp_path / "selected"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "local.json").write_text("{}", encoding="utf-8")
    (outside / "secret.json").write_text("{}", encoding="utf-8")
    junction = root / "linked-directory"
    _junction_or_skip(junction, outside)

    result = discover_files([root], {".json"})

    assert result.files == (root / "local.json",)
    assert result.limits == ("reparse_excluded",)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction test")
def test_discovery_skips_root_beneath_junction(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    nested = outside / "nested"
    nested.mkdir(parents=True)
    (nested / "secret.json").write_text("{}", encoding="utf-8")
    junction = tmp_path / "link"
    _junction_or_skip(junction, outside)

    result = discover_files([junction / "nested"], {".json"})

    assert result.files == ()
    assert result.limits == ("root_reparse_excluded",)


def test_discovery_discards_batch_when_reparse_appears_after_scandir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "selected"
    root.mkdir()
    (root / "secret.json").write_text("{}", encoding="utf-8")
    checks = 0

    def reparse_appears_after_scandir(path: Path) -> bool:
        nonlocal checks
        checks += 1
        return checks >= 3

    monkeypatch.setattr(
        discovery, "_has_reparse_component", reparse_appears_after_scandir
    )

    result = discover_files([root], {".json"})

    assert result.files == ()
    assert result.limits == ("reparse_changed",)
    assert checks == 3


def test_known_config_roots_returns_only_existing_known_directories(
    tmp_path: Path,
) -> None:
    appdata = tmp_path / "appdata"
    local_appdata = tmp_path / "local-appdata"
    userprofile = tmp_path / "profile"
    expected = [
        appdata / "Claude",
        appdata / "Cursor" / "User",
        local_appdata / "OpenAI",
        userprofile / ".config" / "codex",
    ]
    for path in expected:
        path.mkdir(parents=True, exist_ok=True)
    (appdata / "UnrelatedApp").mkdir()

    found = known_config_roots(
        {
            "APPDATA": str(appdata),
            "LOCALAPPDATA": str(local_appdata),
            "USERPROFILE": str(userprofile),
        }
    )

    assert found == sorted(expected)


def test_known_config_roots_ignores_missing_environment_variables() -> None:
    assert known_config_roots({}) == []


def test_known_config_roots_fails_closed_when_resolve_raises_runtime_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    appdata = tmp_path / "appdata"
    (appdata / "Claude").mkdir(parents=True)

    def raise_runtime_error(path: Path, *, strict: bool = False) -> Path:
        raise RuntimeError("synthetic resolution loop")

    monkeypatch.setattr(Path, "resolve", raise_runtime_error)

    assert known_config_roots({"APPDATA": str(appdata)}) == []


def test_known_config_roots_stats_candidate_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    appdata = tmp_path / "appdata"
    candidate = appdata / "Claude"
    candidate.mkdir(parents=True)
    real_lstat = discovery.os.lstat
    candidate_calls = 0

    def identity_resolve(path: Path, *, strict: bool = False) -> Path:
        return path

    def single_candidate_lstat(path: os.PathLike[str]) -> os.stat_result:
        nonlocal candidate_calls
        if Path(path) == candidate:
            candidate_calls += 1
            if candidate_calls > 1:
                raise AssertionError("candidate was statted twice")
        return real_lstat(path)

    monkeypatch.setattr(Path, "resolve", identity_resolve)
    monkeypatch.setattr(discovery.os, "lstat", single_candidate_lstat)

    assert known_config_roots({"APPDATA": str(appdata)}) == [candidate]
    assert candidate_calls == 1


def test_known_config_roots_rejects_directory_linked_outside_allowed_root(
    tmp_path: Path,
) -> None:
    appdata = tmp_path / "appdata"
    outside = tmp_path / "outside"
    appdata.mkdir()
    outside.mkdir()
    _symlink_or_skip(appdata / "Claude", outside, directory=True)

    assert known_config_roots({"APPDATA": str(appdata)}) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows junction test")
def test_known_config_roots_rejects_junction_outside_allowed_root(
    tmp_path: Path,
) -> None:
    appdata = tmp_path / "appdata"
    outside = tmp_path / "outside"
    appdata.mkdir()
    outside.mkdir()
    _junction_or_skip(appdata / "Claude", outside)

    assert known_config_roots({"APPDATA": str(appdata)}) == []
