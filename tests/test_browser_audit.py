import hashlib
import sqlite3
from pathlib import Path

import pytest

from agentguardian.browser_audit import (
    BrowserKind,
    audit_browser_database,
)


def _create_database(path: Path, browser: BrowserKind) -> str:
    raw_url = "https://synthetic.example/private?token=must-not-leak"
    with sqlite3.connect(path) as connection:
        if browser in {BrowserKind.CHROME, BrowserKind.EDGE}:
            connection.executescript(
                """
                CREATE TABLE urls (id INTEGER, url TEXT);
                CREATE TABLE visits (id INTEGER, url INTEGER);
                """
            )
            connection.execute("INSERT INTO urls VALUES (1, ?)", (raw_url,))
            connection.execute("INSERT INTO visits VALUES (1, 1)")
        else:
            connection.executescript(
                """
                CREATE TABLE moz_places (id INTEGER, url TEXT);
                CREATE TABLE moz_historyvisits (id INTEGER, place_id INTEGER);
                """
            )
            connection.execute("INSERT INTO moz_places VALUES (1, ?)", (raw_url,))
            connection.execute("INSERT INTO moz_historyvisits VALUES (1, 1)")
        connection.commit()
    return raw_url


@pytest.mark.parametrize("browser", (BrowserKind.CHROME, BrowserKind.EDGE, BrowserKind.FIREFOX))
def test_browser_audit_reads_fixed_counts_without_returning_raw_data(
    tmp_path: Path, browser: BrowserKind
):
    database = tmp_path / ("History" if browser is not BrowserKind.FIREFOX else "places.sqlite")
    raw_url = _create_database(database, browser)
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    result = audit_browser_database(database, browser)

    assert result.browser is browser
    assert result.counts == (("history_entries", 1), ("visit_entries", 1))
    assert result.raw_data_retained is False
    assert result.temporary_copy_removed is True
    assert raw_url not in repr(result)
    assert str(database) not in repr(result)
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_browser_audit_rejects_unknown_schema_without_leaking_database_error(tmp_path: Path):
    database = tmp_path / "History"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE unrelated (value TEXT)")
        connection.commit()

    with pytest.raises(ValueError, match="BROWSER_SCHEMA_UNSUPPORTED"):
        audit_browser_database(database, BrowserKind.CHROME)


def test_browser_audit_reads_current_sqlite_wal_snapshot_without_raw_data(
    tmp_path: Path,
):
    database = tmp_path / "History"
    raw_urls = (
        "https://synthetic.example/private?token=wal-one",
        "https://synthetic.example/private?token=wal-two",
    )
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA wal_autocheckpoint = 0")
        connection.executescript(
            """
            CREATE TABLE urls (id INTEGER, url TEXT);
            CREATE TABLE visits (id INTEGER, url INTEGER);
            """
        )
        connection.execute("INSERT INTO urls VALUES (1, ?)", (raw_urls[0],))
        connection.execute("INSERT INTO visits VALUES (1, 1)")
        connection.commit()
        connection.execute("INSERT INTO urls VALUES (2, ?)", (raw_urls[1],))
        connection.execute("INSERT INTO visits VALUES (2, 2)")
        connection.commit()
        assert database.with_name("History-wal").is_file()

        result = audit_browser_database(database, BrowserKind.CHROME)

    assert result.counts == (("history_entries", 2), ("visit_entries", 2))
    assert result.raw_data_retained is False
    assert result.temporary_copy_removed is True
    assert all(raw_url not in repr(result) for raw_url in raw_urls)


def test_browser_audit_applies_size_limit_to_sqlite_sidecars(tmp_path: Path):
    database = tmp_path / "History"
    _create_database(database, BrowserKind.CHROME)
    sidecar = database.with_name("History-wal")
    sidecar.write_bytes(b"sidecar")

    with pytest.raises(ValueError, match="BROWSER_PATH_INVALID"):
        audit_browser_database(
            database,
            BrowserKind.CHROME,
            max_bytes=database.stat().st_size,
        )


def test_browser_audit_rejects_reparse_path_without_opening_target(tmp_path: Path):
    database = tmp_path / "History"
    raw_url = _create_database(database, BrowserKind.CHROME)
    linked = tmp_path / "linked-history"
    try:
        linked.symlink_to(database)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"file symlink unavailable: {error.__class__.__name__}")

    with pytest.raises(ValueError, match="BROWSER_PATH_INVALID"):
        audit_browser_database(linked, BrowserKind.CHROME)
    assert raw_url in database.read_text(encoding="utf-8", errors="ignore")
