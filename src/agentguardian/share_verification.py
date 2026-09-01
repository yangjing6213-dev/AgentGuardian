from dataclasses import dataclass
import http.client
import ipaddress
import socket
from collections.abc import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)


MAX_SHARE_RESPONSE_BYTES = 64 * 1024
MAX_SHARE_REDIRECTS = 3
SHARE_TIMEOUT_SECONDS = 5.0
_ALLOWED_CONTENT_TYPES = frozenset(
    {"application/json", "text/html", "text/plain"}
)


@dataclass(frozen=True, slots=True)
class ShareVerificationResult:
    address: str
    reachable: bool
    status_code: int | None
    content_type: str
    bytes_read: int
    redirects_followed: int
    scanned_data_sent: bool
    credentials_sent: bool
    raw_response_retained: bool
    limits: tuple[str, ...]


class _RedirectLimitError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _ResolvedEndpoint:
    family: int
    socket_type: int
    protocol: int
    address: tuple


def verify_public_share(
    url: str,
    *,
    timeout: float = SHARE_TIMEOUT_SECONDS,
    max_bytes: int = MAX_SHARE_RESPONSE_BYTES,
    max_redirects: int = MAX_SHARE_REDIRECTS,
    allow_private_hosts: bool = False,
) -> ShareVerificationResult:
    """Probe a user-provided public URL without sending local audit data."""
    if (
        type(url) is not str
        or type(timeout) not in (int, float)
        or timeout <= 0
        or type(max_bytes) is not int
        or max_bytes <= 0
        or type(max_redirects) is not int
        or max_redirects < 0
        or type(allow_private_hosts) is not bool
    ):
        raise ValueError("SHARE_INPUT_INVALID")
    request_url, address = _validated_url(url, allow_private_hosts)
    redirect_handler = _BoundedRedirectHandler(
        max_redirects=max_redirects,
        allow_private_hosts=allow_private_hosts,
    )
    request = Request(
        request_url,
        method="GET",
        headers={
            "Accept": "application/json, text/plain, text/html;q=0.9",
            "User-Agent": "AgentGuardian-share-verifier/0.1",
        },
    )
    try:
        opener = build_opener(
            ProxyHandler({}),
            redirect_handler,
            _PinnedHTTPHandler(allow_private_hosts),
            _PinnedHTTPSHandler(allow_private_hosts),
        )
        with opener.open(request, timeout=timeout) as response:
            status_code = response.getcode()
            content_type = response.headers.get_content_type()
            if content_type not in _ALLOWED_CONTENT_TYPES:
                return _result(
                    address,
                    status_code,
                    content_type,
                    redirect_handler.count,
                    ("content_type_rejected",),
                )
            declared_size = _content_length(response.headers)
            if declared_size is not None and declared_size > max_bytes:
                return _result(
                    address,
                    status_code,
                    content_type,
                    redirect_handler.count,
                    ("response_size_limit",),
                )
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                return _result(
                    address,
                    status_code,
                    content_type,
                    redirect_handler.count,
                    ("response_size_limit",),
                )
            return ShareVerificationResult(
                address=address,
                reachable=True,
                status_code=status_code,
                content_type=content_type,
                bytes_read=len(body),
                redirects_followed=redirect_handler.count,
                scanned_data_sent=False,
                credentials_sent=False,
                raw_response_retained=False,
                limits=(),
            )
    except _RedirectLimitError:
        return _result(
            address,
            None,
            "unknown",
            redirect_handler.count,
            ("redirect_limit",),
        )
    except HTTPError as error:
        return _result(
            address,
            error.code,
            error.headers.get_content_type() if error.headers else "unknown",
            redirect_handler.count,
            ("http_error",),
        )
    except (TimeoutError, URLError, OSError):
        return _result(
            address,
            None,
            "unknown",
            redirect_handler.count,
            ("network_error",),
        )


class _BoundedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, *, max_redirects: int, allow_private_hosts: bool) -> None:
        self.max_redirects = max_redirects
        self.allow_private_hosts = allow_private_hosts
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.count >= self.max_redirects:
            raise _RedirectLimitError
        target, _address = _validated_url(newurl, self.allow_private_hosts)
        self.count += 1
        return super().redirect_request(req, fp, code, msg, headers, target)


class _PinnedHTTPHandler(HTTPHandler):
    def __init__(self, allow_private_hosts: bool) -> None:
        super().__init__()
        self.allow_private_hosts = allow_private_hosts

    def http_open(self, request):
        endpoint = _resolve_endpoint(request.full_url, self.allow_private_hosts)
        return self.do_open(
            _pinned_connection_factory(http.client.HTTPConnection, endpoint),
            request,
        )


class _PinnedHTTPSHandler(HTTPSHandler):
    def __init__(self, allow_private_hosts: bool) -> None:
        super().__init__()
        self.allow_private_hosts = allow_private_hosts

    def https_open(self, request):
        endpoint = _resolve_endpoint(request.full_url, self.allow_private_hosts)
        return self.do_open(
            _pinned_connection_factory(http.client.HTTPSConnection, endpoint),
            request,
            context=self._context,
        )


def _resolve_endpoint(url: str, allow_private_hosts: bool) -> _ResolvedEndpoint:
    parsed = urlsplit(url)
    host = parsed.hostname
    if host is None:
        raise ValueError("SHARE_URL_INVALID")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    records = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    endpoints = []
    for family, socket_type, protocol, _canonical_name, address in records:
        if family not in {socket.AF_INET, socket.AF_INET6} or not address:
            continue
        try:
            resolved = ipaddress.ip_address(str(address[0]).split("%", 1)[0])
        except ValueError:
            raise OSError("SHARE_DNS_INVALID") from None
        if not allow_private_hosts and not _is_public_address(resolved):
            raise ValueError("SHARE_PRIVATE_HOST_REJECTED")
        endpoints.append(
            _ResolvedEndpoint(family, socket_type, protocol, address)
        )
    if not endpoints:
        raise OSError("SHARE_DNS_EMPTY")
    return endpoints[0]


def _is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.is_global and not address.is_multicast


def _pinned_connection_factory(connection_class, endpoint: _ResolvedEndpoint):
    def create(host, **kwargs):
        connection = connection_class(host, **kwargs)
        connection._create_connection = lambda _address, timeout, source_address: (
            _open_pinned_socket(endpoint, timeout, source_address)
        )
        return connection

    return create


def _open_pinned_socket(
    endpoint: _ResolvedEndpoint,
    timeout: float,
    source_address,
):
    connection = socket.socket(
        endpoint.family,
        endpoint.socket_type,
        endpoint.protocol,
    )
    try:
        connection.settimeout(timeout)
        if source_address:
            connection.bind(source_address)
        connection.connect(endpoint.address)
    except BaseException:
        connection.close()
        raise
    return connection


def _validated_url(url: str, allow_private_hosts: bool) -> tuple[str, str]:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            raise ValueError
        if parsed.query:
            raise ValueError("SHARE_URL_QUERY_REJECTED")
        if parsed.fragment:
            raise ValueError("SHARE_URL_FRAGMENT_REJECTED")
        port = parsed.port
        host = parsed.hostname.casefold()
    except ValueError as error:
        if str(error) in {
            "SHARE_URL_QUERY_REJECTED",
            "SHARE_URL_FRAGMENT_REJECTED",
        }:
            raise
        raise ValueError("SHARE_URL_INVALID") from None
    if not allow_private_hosts and _is_private_host(host):
        raise ValueError("SHARE_PRIVATE_HOST_REJECTED")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port not in {80, 443}:
        netloc = f"{netloc}:{port}"
    address = f"{parsed.scheme}://{netloc}"
    return parsed.geturl(), address


def _is_private_host(host: str) -> bool:
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not _is_public_address(address)


def _content_length(headers: Mapping[str, str]) -> int | None:
    raw = headers.get("Content-Length")
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _result(
    address: str,
    status_code: int | None,
    content_type: str,
    redirects: int,
    limits: tuple[str, ...],
) -> ShareVerificationResult:
    return ShareVerificationResult(
        address=address,
        reachable=False,
        status_code=status_code,
        content_type=content_type,
        bytes_read=0,
        redirects_followed=redirects,
        scanned_data_sent=False,
        credentials_sent=False,
        raw_response_retained=False,
        limits=limits,
    )
