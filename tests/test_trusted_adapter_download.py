import hashlib
import importlib.util
import io
import errno
import os
from pathlib import Path
import subprocess
import sys

import pytest


PROJECT_ROOT = Path(__file__).parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "download_trusted_mcp_adapter.py"


def _load_download_module():
    assert SCRIPT_PATH.is_file(), "trusted adapter downloader is missing"
    spec = importlib.util.spec_from_file_location("download_trusted_mcp_adapter", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeResponse(io.BytesIO):
    status = 200

    def __init__(self, payload: bytes, url: str, *, content_length: int | None = None):
        super().__init__(payload)
        self._url = url
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class _FakeOpener:
    def __init__(self, response: _FakeResponse):
        self.response = response
        self.request_url = None
        self.timeout = None

    def open(self, request, *, timeout: int):
        self.request_url = request.full_url
        self.timeout = timeout
        return self.response


def _directory_link_or_skip(link: Path, target: Path) -> None:
    if os.name == "nt":
        junction = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
        )
        if junction.returncode:
            pytest.skip(f"junction creation is unavailable: {junction.stderr.strip()}")
        return
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EPERM, errno.ENOSYS}:
            pytest.skip(f"directory symlink creation is unavailable: {error}")
        raise


def test_download_trusted_adapter_streams_exact_hash_to_new_file(tmp_path: Path) -> None:
    downloader = _load_download_module()
    url = "https://artifacts.example/AgentGuardianMcpAdapter.exe"
    payload = b"trusted-adapter"
    opener = _FakeOpener(_FakeResponse(payload, url, content_length=len(payload)))

    result = downloader.download_trusted_adapter(
        url,
        tmp_path,
        hashlib.sha256(payload).hexdigest(),
        opener=opener,
        max_bytes=64,
        timeout_seconds=17,
    )

    assert result.name == "AgentGuardianMcpAdapter.exe"
    assert result.parent.parent == tmp_path
    assert result.read_bytes() == payload
    assert opener.request_url == url
    assert opener.timeout == 17


@pytest.mark.parametrize(
    "url",
    (
        "http://artifacts.example/AgentGuardianMcpAdapter.exe",
        "https:///AgentGuardianMcpAdapter.exe",
        "https://user:password@artifacts.example/AgentGuardianMcpAdapter.exe",
        "https://artifacts.example/AgentGuardianMcpAdapter.exe?token=secret",
        "https://artifacts.example/AgentGuardianMcpAdapter.exe#fragment",
    ),
)
def test_download_trusted_adapter_rejects_unsafe_urls(tmp_path: Path, url: str) -> None:
    downloader = _load_download_module()

    with pytest.raises(ValueError, match="absolute HTTPS URL"):
        downloader.download_trusted_adapter(
            url,
            tmp_path,
            "0" * 64,
            opener=_FakeOpener(_FakeResponse(b"", url)),
        )


def test_download_trusted_adapter_rejects_redirects() -> None:
    downloader = _load_download_module()

    assert (
        downloader.NoRedirectHandler().redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "https://other.example/AgentGuardianMcpAdapter.exe",
        )
        is None
    )


def test_download_trusted_adapter_rejects_declared_oversize_before_write(
    tmp_path: Path,
) -> None:
    downloader = _load_download_module()
    url = "https://artifacts.example/AgentGuardianMcpAdapter.exe"
    opener = _FakeOpener(_FakeResponse(b"small", url, content_length=65))

    with pytest.raises(ValueError, match="size limit"):
        downloader.download_trusted_adapter(
            url,
            tmp_path,
            hashlib.sha256(b"small").hexdigest(),
            opener=opener,
            max_bytes=64,
        )

    assert tuple(tmp_path.iterdir()) == ()


def test_download_trusted_adapter_rejects_invalid_content_length(tmp_path: Path) -> None:
    downloader = _load_download_module()
    url = "https://artifacts.example/AgentGuardianMcpAdapter.exe"
    response = _FakeResponse(b"payload", url)
    response.headers["Content-Length"] = "not-an-integer"

    with pytest.raises(ValueError, match="Content-Length"):
        downloader.download_trusted_adapter(
            url,
            tmp_path,
            hashlib.sha256(b"payload").hexdigest(),
            opener=_FakeOpener(response),
        )

    assert tuple(tmp_path.iterdir()) == ()


def test_download_trusted_adapter_removes_partial_oversize_file(tmp_path: Path) -> None:
    downloader = _load_download_module()
    url = "https://artifacts.example/AgentGuardianMcpAdapter.exe"
    opener = _FakeOpener(_FakeResponse(b"0123456789", url))

    with pytest.raises(ValueError, match="size limit"):
        downloader.download_trusted_adapter(
            url,
            tmp_path,
            hashlib.sha256(b"0123456789").hexdigest(),
            opener=opener,
            max_bytes=5,
        )

    assert tuple(tmp_path.iterdir()) == ()


def test_download_trusted_adapter_removes_hash_mismatch(tmp_path: Path) -> None:
    downloader = _load_download_module()
    url = "https://artifacts.example/AgentGuardianMcpAdapter.exe"
    opener = _FakeOpener(_FakeResponse(b"wrong", url))

    with pytest.raises(ValueError, match="SHA-256"):
        downloader.download_trusted_adapter(
            url,
            tmp_path,
            "0" * 64,
            opener=opener,
        )

    assert tuple(tmp_path.iterdir()) == ()


def test_download_trusted_adapter_rejects_reparse_temporary_root(tmp_path: Path) -> None:
    downloader = _load_download_module()
    real_root = tmp_path / "real"
    linked_root = tmp_path / "linked"
    real_root.mkdir()
    _directory_link_or_skip(linked_root, real_root)

    with pytest.raises(ValueError, match="reparse"):
        downloader.download_trusted_adapter(
            "https://artifacts.example/AgentGuardianMcpAdapter.exe",
            linked_root,
            hashlib.sha256(b"payload").hexdigest(),
            opener=_FakeOpener(
                _FakeResponse(
                    b"payload",
                    "https://artifacts.example/AgentGuardianMcpAdapter.exe",
                )
            ),
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows sharing semantics only")
def test_exclusive_download_writer_blocks_write_and_replacement(tmp_path: Path) -> None:
    downloader = _load_download_module()
    target = tmp_path / "AgentGuardianMcpAdapter.exe"
    replacement = tmp_path / "replacement.exe"
    replacement.write_bytes(b"replacement")

    with downloader._exclusive_binary_writer(target) as output:
        output.write(b"downloaded")
        output.flush()
        with pytest.raises(OSError):
            target.write_bytes(b"changed")
        with pytest.raises(OSError):
            os.replace(replacement, target)

    assert target.read_bytes() == b"downloaded"


def test_exclusive_download_writer_deletes_on_failure(tmp_path: Path) -> None:
    downloader = _load_download_module()
    target = tmp_path / "AgentGuardianMcpAdapter.exe"

    with pytest.raises(ValueError, match="synthetic failure"):
        with downloader._exclusive_binary_writer(target) as output:
            output.write(b"partial")
            raise ValueError("synthetic failure")

    assert not target.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle paths only")
def test_exclusive_writer_rejects_junction_destination(tmp_path: Path) -> None:
    downloader = _load_download_module()
    real_root = tmp_path / "real"
    linked_root = tmp_path / "linked"
    real_root.mkdir()
    _directory_link_or_skip(linked_root, real_root)
    target = linked_root / "AgentGuardianMcpAdapter.exe"

    with pytest.raises(ValueError, match="resolved outside"):
        with downloader._exclusive_binary_writer(target) as output:
            output.write(b"redirected")

    assert not (real_root / "AgentGuardianMcpAdapter.exe").exists()
