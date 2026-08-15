from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest

from agentguardian.share_verification import verify_public_share


class _Handler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):  # noqa: N802 - stdlib HTTP handler API
        self.__class__.requests.append(dict(self.headers))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
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


def test_share_verification_enforces_response_size_limit(public_server):
    result = verify_public_share(
        public_server,
        max_bytes=4,
        allow_private_hosts=True,
    )

    assert result.reachable is False
    assert result.limits == ("response_size_limit",)
    assert result.bytes_read == 0
