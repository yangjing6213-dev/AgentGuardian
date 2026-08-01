import ntpath
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

_KNOWN_CONFIG_LOCATIONS = (
    ("APPDATA", (), (("Claude",), ("Cursor", "User"), ("Windsurf", "User"))),
    ("LOCALAPPDATA", (), (("OpenAI",),)),
    ("USERPROFILE", (".config",), (("claude",), ("codex",))),
)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    files: tuple[Path, ...]
    limits: tuple[str, ...]
    entries_seen: int


def discover_files(
    roots: list[Path],
    suffixes: set[str],
    max_files: int = 50_000,
    max_entries: int = 100_000,
) -> DiscoveryResult:
    """Audit regular files from explicit roots as a bounded stable snapshot.

    This read-only Alpha rechecks reparse components around each directory scan.
    It has no handle-based isolation.
    It does not defend against an active local attacker repeatedly replacing paths
    between checks.
    """
    if max_files <= 0:
        raise ValueError("max_files must be positive")
    if max_entries <= 0:
        raise ValueError("max_entries must be positive")

    wanted_suffixes = {suffix.lower() for suffix in suffixes}
    accepted_roots: list[Path] = []
    limits: list[str] = []
    for root in roots:
        if _is_windows_root(root):
            raise ValueError("Windows root paths are not allowed")
        path = Path(root)
        if not _has_reparse_component(path):
            accepted_roots.append(path)
        else:
            limits.append("root_reparse_excluded")

    pending = sorted(accepted_roots, key=_sort_key, reverse=True)
    seen_directories: set[str] = set()
    found: list[Path] = []
    entries_seen = 0

    while pending:
        directory = pending.pop()
        directory_key = os.path.normcase(os.path.abspath(directory))
        if directory_key in seen_directories:
            continue
        seen_directories.add(directory_key)

        if _has_reparse_component(directory):
            limits.append("reparse_excluded")
            continue

        try:
            directory_stat = os.lstat(directory)
            if not stat.S_ISDIR(directory_stat.st_mode) or _is_reparse(directory_stat):
                limits.append("directory_excluded")
                continue
            with os.scandir(directory) as iterator:
                entries = []
                for entry in iterator:
                    if entries_seen >= max_entries:
                        limits.append("entry_limit_reached")
                        return _discovery_result(found, limits, entries_seen)
                    entries_seen += 1
                    entries.append(entry)
                entries.sort(key=_entry_sort_key)
        except OSError:
            limits.append("directory_read_limited")
            continue

        if _has_reparse_component(directory):
            limits.append("reparse_changed")
            continue

        child_directories: list[Path] = []
        for entry in entries:
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError:
                limits.append("entry_read_limited")
                continue
            if _is_reparse(entry_stat):
                limits.append("reparse_excluded")
                continue

            path = Path(entry.path)
            if stat.S_ISDIR(entry_stat.st_mode):
                child_directories.append(path)
            elif stat.S_ISREG(entry_stat.st_mode) and path.suffix.lower() in wanted_suffixes:
                found.append(path)
                if len(found) == max_files:
                    limits.append("file_limit_reached")
                    return _discovery_result(found, limits, entries_seen)

        pending.extend(reversed(child_directories))

    return _discovery_result(found, limits, entries_seen)


def _discovery_result(
    found: list[Path], limits: list[str], entries_seen: int
) -> DiscoveryResult:
    return DiscoveryResult(
        files=tuple(sorted(found, key=_sort_key)),
        limits=tuple(dict.fromkeys(limits)),
        entries_seen=entries_seen,
    )


def known_config_roots(environ: Mapping[str, str]) -> list[Path]:
    found: list[Path] = []
    for variable, base_parts, relative_paths in _KNOWN_CONFIG_LOCATIONS:
        value = environ.get(variable)
        if not value:
            continue
        allowed_root = Path(value).joinpath(*base_parts)
        for relative_path in relative_paths:
            candidate = allowed_root.joinpath(*relative_path)
            if _is_allowed_directory(candidate, allowed_root):
                found.append(candidate)
    return sorted(found, key=_sort_key)


def _is_allowed_directory(candidate: Path, allowed_root: Path) -> bool:
    try:
        resolved_root = allowed_root.resolve(strict=True)
        candidate.resolve(strict=True).relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        return False

    try:
        candidate_stat = os.lstat(candidate)
    except OSError:
        return False
    if _is_reparse(candidate_stat):
        return False
    if candidate == allowed_root:
        return stat.S_ISDIR(candidate_stat.st_mode)

    current = candidate.parent
    while True:
        try:
            current_stat = os.lstat(current)
        except OSError:
            return False
        if _is_reparse(current_stat):
            return False
        if current == allowed_root:
            return stat.S_ISDIR(candidate_stat.st_mode)
        current = current.parent


def _is_reparse(path_stat: os.stat_result) -> bool:
    return bool(getattr(path_stat, "st_file_attributes", 0) & _REPARSE_POINT)


def _entry_sort_key(entry: os.DirEntry[str]) -> tuple[str, str]:
    return entry.name.casefold(), entry.name


def _is_windows_root(path: os.PathLike[str]) -> bool:
    windows_path = PureWindowsPath(ntpath.normpath(os.fspath(path)))
    return bool(windows_path.root) and windows_path == PureWindowsPath(
        windows_path.anchor
    )


def _has_reparse_component(path: Path) -> bool:
    absolute_path = Path(os.path.abspath(path))
    for component in (*reversed(absolute_path.parents), absolute_path):
        try:
            component_stat = os.lstat(component)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if stat.S_ISLNK(component_stat.st_mode) or _is_reparse(component_stat):
            return True
    return False


def _sort_key(path: Path) -> tuple[str, str]:
    value = os.fspath(path)
    return value.casefold(), value
