import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading

import pytest

from agentguardian import share_verification
from agentguardian.share_verification import (
    validate_public_share_url,
    verify_public_share,
)


class _Handler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):  # noqa: N802 - stdlib HTTP handler API
        self.__class__.requests.append(dict(self.headers))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        if self.path == "/private-redirect":
            self.send_response(302)
            self.send_header("Location", "http://private-target.example/final")
            self.end_headers()
            return
        body = b"synthetic public response"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


@pytest.fixture()
def public_server():
    _Handler.requests.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_share_verification_reads_bounded_public_response_without_user_data(public_server):
    result = verify_public_share(public_server, allow_private_hosts=True)

    assert result.reachable is True
    assert result.status_code == 200
    assert result.content_type == "text/plain"
    assert result.bytes_read > 0
    assert result.redirects_followed == 0
    assert result.scanned_data_sent is False
    assert result.credentials_sent is False
    assert result.raw_response_retained is False
    request_headers = _Handler.requests[0]
    assert "Authorization" not in request_headers
    assert "Cookie" not in request_headers


def test_share_verification_bounds_redirects(public_server):
    result = verify_public_share(
        f"{public_server}/redirect",
        max_redirects=0,
        allow_private_hosts=True,
    )

    assert result.reachable is False
    assert result.limits == ("redirect_limit",)
    assert result.raw_response_retained is False


def test_share_verification_rejects_query_and_non_http_urls(public_server):
    with pytest.raises(ValueError, match="SHARE_URL_QUERY_REJECTED"):
        verify_public_share(f"{public_server}/share?token=synthetic")
    with pytest.raises(ValueError, match="SHARE_URL_INVALID"):
        verify_public_share("file:///C:/synthetic-share.txt")
    with pytest.raises(ValueError, match="SHARE_PRIVATE_HOST_REJECTED"):
        verify_public_share(public_server)


def test_validate_public_share_url_performs_no_dns_or_network(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("dns")),
    )

    request_url, address = validate_public_share_url("https://example.com/path")

    assert request_url == "https://example.com/path"
    assert address == "https://example.com"


def test_share_verification_enforces_response_size_limit(public_server):
    result = verify_public_share(
        public_server,
        max_bytes=4,
        allow_private_hosts=True,
    )

    assert result.reachable is False
    assert result.limits == ("response_size_limit",)
    assert result.bytes_read == 0


def test_share_verification_rejects_hostname_resolving_to_private_address(
    monkeypatch: pytest.MonkeyPatch,
):
    socket_calls = []

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("192.168.0.6", 443),
            )
        ],
    )

    def fail_socket(*args, **kwargs):
        socket_calls.append((args, kwargs))
        raise OSError("connection must not be attempted")

    monkeypatch.setattr(socket, "socket", fail_socket)

    with pytest.raises(ValueError, match="^SHARE_PRIVATE_HOST_REJECTED$"):
        verify_public_share("https://public-looking.example/")

    assert socket_calls == []


def test_share_verification_rejects_mixed_public_and_private_dns_answers(
    monkeypatch: pytest.MonkeyPatch,
):
    socket_calls = []
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            ),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("fd00::6", 443, 0, 0),
            ),
        ],
    )

    def fail_socket(*args, **kwargs):
        socket_calls.append((args, kwargs))
        raise OSError("connection must not be attempted")

    monkeypatch.setattr(socket, "socket", fail_socket)

    with pytest.raises(ValueError, match="^SHARE_PRIVATE_HOST_REJECTED$"):
        verify_public_share("https://mixed.example/")

    assert socket_calls == []


def test_share_verification_pins_one_resolution_and_preserves_host_header(
    public_server,
    monkeypatch: pytest.MonkeyPatch,
):
    real_getaddrinfo = socket.getaddrinfo
    resolution_count = 0

    def resolve_once(host, port, *args, **kwargs):
        nonlocal resolution_count
        if host != "share.example":
            return real_getaddrinfo(host, port, *args, **kwargs)
        resolution_count += 1
        address = "127.0.0.1" if resolution_count == 1 else "127.0.0.2"
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (address, port),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", resolve_once)
    port = public_server.rsplit(":", 1)[1]

    result = verify_public_share(
        f"http://share.example:{port}/",
        allow_private_hosts=True,
    )

    assert result.reachable is True
    assert resolution_count == 1
    assert _Handler.requests[0]["Host"] == f"share.example:{port}"


def test_share_verification_rejects_redirect_resolving_to_private_address(
    public_server,
    monkeypatch: pytest.MonkeyPatch,
):
    real_getaddrinfo = socket.getaddrinfo

    def resolve_target(host, port, *args, **kwargs):
        if host != "private-target.example":
            return real_getaddrinfo(host, port, *args, **kwargs)
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("10.0.0.6", port),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", resolve_target)
    monkeypatch.setattr(
        share_verification,
        "_is_public_address",
        lambda address: str(address) == "127.0.0.1",
    )

    with pytest.raises(ValueError, match="^SHARE_PRIVATE_HOST_REJECTED$"):
        verify_public_share(f"{public_server}/private-redirect")

    assert len(_Handler.requests) == 1


def test_pinned_https_connection_preserves_original_sni(
    monkeypatch: pytest.MonkeyPatch,
):
    endpoint = share_verification._ResolvedEndpoint(
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        ("93.184.216.34", 443),
    )
    server_names = []

    class FakeSocket:
        def setsockopt(self, *_args):
            return None

    class FakeContext:
        def wrap_socket(self, connection, *, server_hostname):
            server_names.append(server_hostname)
            return connection

    monkeypatch.setattr(
        share_verification,
        "_open_pinned_socket",
        lambda *_args: FakeSocket(),
    )
    factory = share_verification._pinned_connection_factory(
        http.client.HTTPSConnection,
        endpoint,
    )
    connection = factory(
        "secure.example",
        context=FakeContext(),
        timeout=1.0,
    )

    connection.connect()

    assert server_names == ["secure.example"]
