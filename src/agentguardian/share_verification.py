from dataclasses import dataclass
import ipaddress
from collections.abc import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


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
        with build_opener(redirect_handler).open(request, timeout=timeout) as response:
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
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
    )


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
