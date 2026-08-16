from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from agentguardian.file_integrity import (
    MAX_HASHED_FILE_BYTES,
    FileSizeLimitExceeded,
    bounded_file_sha256,
)


def test_bounded_file_sha256_accepts_the_exact_limit(tmp_path: Path) -> None:
    target = tmp_path / "adapter.exe"
    target.write_bytes(b"12345")

    assert bounded_file_sha256(target, max_bytes=5) == hashlib.sha256(b"12345").hexdigest()


def test_bounded_file_sha256_rejects_one_byte_over_the_limit(tmp_path: Path) -> None:
    target = tmp_path / "adapter.exe"
    target.write_bytes(b"123456")

    with pytest.raises(FileSizeLimitExceeded):
        bounded_file_sha256(target, max_bytes=5)


def test_default_adapter_limit_rejects_sparse_64_mib_plus_one(tmp_path: Path) -> None:
    target = tmp_path / "adapter.exe"
    with target.open("wb") as output:
        output.seek(MAX_HASHED_FILE_BYTES)
        output.write(b"x")

    with pytest.raises(FileSizeLimitExceeded):
        bounded_file_sha256(target)
