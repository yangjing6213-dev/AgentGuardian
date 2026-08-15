from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile


MAX_BROWSER_DB_BYTES = 256 * 1024 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class BrowserKind(str, Enum):
    CHROME = "chrome"
    EDGE = "edge"
    FIREFOX = "firefox"


@dataclass(frozen=True, slots=True)
class BrowserAuditResult:
    browser: BrowserKind
    counts: tuple[tuple[str, int], ...]
    raw_data_retained: bool
    temporary_copy_removed: bool
    limits: tuple[str, ...] = ()


def audit_browser_database(
    path: str | Path,
    browser: BrowserKind,
    *,
    max_bytes: int = MAX_BROWSER_DB_BYTES,
) -> BrowserAuditResult:
    """Read fixed aggregate fields from a temporary read-only browser DB copy."""
    if type(browser) is not BrowserKind or type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("BROWSER_INPUT_INVALID")
    candidate = Path(path)
    source_files = _validated_database_files(candidate, max_bytes)

    temporary_root = Path(tempfile.mkdtemp(prefix="agentguardian-browser-"))
    temporary_copy = temporary_root / "database.sqlite"
    counts: tuple[tuple[str, int], ...] | None = None
    try:
        for source in source_files:
            suffix = source.name[len(candidate.name) :]
            shutil.copyfile(source, temporary_root / f"database.sqlite{suffix}")
        counts = _read_fixed_counts(temporary_copy, browser)
    except ValueError:
        raise
    except (OSError, sqlite3.DatabaseError):
        raise ValueError("BROWSER_DB_UNREADABLE") from None
    finally:
        try:
            shutil.rmtree(temporary_root)
        except OSError:
            raise ValueError("BROWSER_TEMP_CLEANUP_FAILED") from None

    if counts is None or temporary_root.exists():
        raise ValueError("BROWSER_TEMP_CLEANUP_FAILED")
    return BrowserAuditResult(
        browser=browser,
        counts=counts,
        raw_data_retained=False,
        temporary_copy_removed=True,
    )


def _validated_database_files(path: Path, max_bytes: int) -> tuple[Path, ...]:
    if not path.is_absolute():
        raise ValueError("BROWSER_PATH_INVALID")
    source_files: list[Path] = []
    total_bytes = 0
    for suffix in ("", *_SQLITE_SIDECAR_SUFFIXES):
        candidate = path if not suffix else path.with_name(path.name + suffix)
        try:
            path_stat = os.lstat(candidate)
        except OSError:
            if suffix:
                continue
            raise ValueError("BROWSER_PATH_INVALID") from None
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or stat.S_ISLNK(path_stat.st_mode)
            or bool(getattr(path_stat, "st_file_attributes", 0) & _REPARSE_POINT)
        ):
            raise ValueError("BROWSER_PATH_INVALID")
        total_bytes += path_stat.st_size
        if total_bytes > max_bytes:
            raise ValueError("BROWSER_PATH_INVALID")
        source_files.append(candidate)
    return tuple(source_files)


def _read_fixed_counts(path: Path, browser: BrowserKind) -> tuple[tuple[str, int], ...]:
    if browser in {BrowserKind.CHROME, BrowserKind.EDGE}:
        tables = {"urls", "visits"}
        queries = (
            ("history_entries", "SELECT COUNT(*) FROM urls"),
            ("visit_entries", "SELECT COUNT(*) FROM visits"),
        )
    else:
        tables = {"moz_places", "moz_historyvisits"}
        queries = (
            ("history_entries", "SELECT COUNT(*) FROM moz_places"),
            ("visit_entries", "SELECT COUNT(*) FROM moz_historyvisits"),
        )

    try:
        connection = sqlite3.connect(
            f"file:{path.as_posix()}?mode=ro",
            uri=True,
            timeout=1.0,
        )
        try:
            connection.execute("PRAGMA query_only = ON")
            existing_tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            if not tables <= existing_tables:
                raise ValueError("BROWSER_SCHEMA_UNSUPPORTED")
            values = tuple(
                (name, _validated_count(connection.execute(query).fetchone()))
                for name, query in queries
            )
        finally:
            connection.close()
    except ValueError:
        raise
    except sqlite3.DatabaseError:
        raise ValueError("BROWSER_DB_UNREADABLE") from None
    return values


def _validated_count(row: tuple[object, ...] | None) -> int:
    if row is None or len(row) != 1 or type(row[0]) is not int or row[0] < 0:
        raise ValueError("BROWSER_DB_UNREADABLE")
    return row[0]
