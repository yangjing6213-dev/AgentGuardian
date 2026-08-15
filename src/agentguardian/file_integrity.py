"""Bounded streaming helpers for executable integrity checks."""

from __future__ import annotations

import hashlib
from pathlib import Path


MAX_MCP_ADAPTER_BYTES = 64 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024


class FileSizeLimitExceeded(ValueError):
    """Raised when a file exceeds its declared integrity-check boundary."""


def bounded_file_sha256(
    path: Path,
    *,
    max_bytes: int = MAX_MCP_ADAPTER_BYTES,
) -> str:
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("FILE_HASH_SIZE_LIMIT_INVALID")
    digest = hashlib.sha256()
    total = 0
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(_HASH_CHUNK_BYTES), b""):
            total += len(block)
            if total > max_bytes:
                raise FileSizeLimitExceeded
            digest.update(block)
    return digest.hexdigest()
