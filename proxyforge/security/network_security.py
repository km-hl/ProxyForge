"""Outbound HTTP safeguards for user-configured subscription sources."""

from __future__ import annotations

import ipaddress
from contextlib import closing
from functools import partial
import socket
import urllib.parse
from typing import Iterable, Optional

import requests
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError

from .outbound_budget import DEFAULT_TOTAL_TIMEOUT, RequestBudget, _positive_seconds, resolve_with_budget


ALLOWED_SCHEMES = {"http", "https"}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_REDIRECTS = 3


class UnsafeOutboundUrl(ValueError):
    pass


class ResponseTooLarge(ValueError):
    pass


def _resolved_addresses(hostname: str, port: int) -> Iterable[str]:
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeOutboundUrl("订阅地址无法解析") from exc
    return tuple(dict.fromkeys(record[4][0] for record in records))


def _is_public_address(value: str) -> bool:
    if "%" in value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast and not address.is_reserved


def _validated_addresses(parsed, budget=None) -> tuple[str, ...]:
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    addresses = (tuple(_resolved_addresses(parsed.hostname, port)) if budget is None else
                 resolve_with_budget(_resolved_addresses, parsed.hostname, port, budget))
    if not addresses or any(not _is_public_address(item) for item in addresses):
        raise UnsafeOutboundUrl("订阅地址解析到了私有或保留网络")
    return addresses


def validate_outbound_url(value: str, resolve_dns: bool = False) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(value).strip())
    except ValueError as exc:
        raise UnsafeOutboundUrl("订阅地址格式无效") from exc

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeOutboundUrl("订阅地址只允许 HTTP 或 HTTPS")
    if not parsed.hostname:
        raise UnsafeOutboundUrl("订阅地址缺少主机名")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise UnsafeOutboundUrl("订阅地址端口无效") from exc
    if parsed_port == 0:
        raise UnsafeOutboundUrl("订阅地址端口无效")

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        raise UnsafeOutboundUrl("订阅地址不能指向本机或内部网络")

    try:
        literal_address = ipaddress.ip_address(hostname)
    except ValueError:
        literal_address = None
    if literal_address is not None and not _is_public_address(hostname):
        raise UnsafeOutboundUrl("订阅地址不能指向私有或保留网络")

    if resolve_dns:
        _validated_addresses(parsed)

    return urllib.parse.urlunsplit(parsed)


class _PinnedConnectionMixin:
    def __init__(self, *args, pinned_addresses, budget=None, **kwargs):
        self._pinned_addresses = pinned_addresses
        self._budget = budget
        super().__init__(*args, **kwargs)

    def connect(self):
        super().connect()
        if self._budget is not None:
            # HTTPS replaces the raw socket during the TLS handshake. Track
            # the wrapped socket too, before HTTP can start reading headers.
            self._budget.watch_socket(self.sock)

    def _new_conn(self):
        # Numeric socket.connect avoids urllib3's second getaddrinfo. Keep
        # self.host unchanged for HTTP Host, TLS SNI and certificate matching.
        last_error = None
        for value in self._pinned_addresses:
            if self._budget is not None:
                self._budget.check()
            address = ipaddress.ip_address(value)
            family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
            destination = (str(address), self.port, 0, 0) if address.version == 6 else (str(address), self.port)
            sock = None
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(self.timeout if self._budget is None else min(self.timeout, self._budget.remaining()))
                if self._budget is not None:
                    self._budget.watch_socket(sock)
                for option in self.socket_options or ():
                    sock.setsockopt(*option)
                sock.connect(destination)
                if self._budget is not None:
                    # TLS handshake must receive only the remaining budget.
                    sock.settimeout(min(self.timeout, self._budget.remaining()))
                return sock
            except OSError as exc:
                last_error = exc
                if sock is not None:
                    sock.close()
        if isinstance(last_error, socket.timeout):
            raise ConnectTimeoutError(self, "订阅连接超时") from last_error
        raise NewConnectionError(self, "无法连接已验证的订阅地址") from last_error


class _PinnedHTTPConnection(_PinnedConnectionMixin, HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, HTTPSConnection):
    pass


class _PinnedAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, url, addresses, budget=None):
        self._url = url
        self._addresses = addresses
        self._budget = budget
        self._pools = []
        super().__init__(max_retries=0)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        if request.url != self._url or proxies:
            raise UnsafeOutboundUrl("订阅连接目标或代理发生变化")
        pool = super().get_connection_with_tls_context(request, verify, proxies, cert)
        connection_type = _PinnedHTTPSConnection if request.url.startswith("https://") else _PinnedHTTPConnection
        # Per-instance constructor: never mutate urllib3's global pool classes.
        pool.ConnectionCls = partial(connection_type, pinned_addresses=self._addresses, budget=self._budget)
        self._pools.append(pool)
        return pool

    def close(self):
        for pool in self._pools:
            pool.close()
        self._pools.clear()
        super().close()


class _OutboundSession(requests.Session):
    def resolve_redirects(self, *args, **kwargs):
        # safe_get owns every redirect. Even allow_redirects=False otherwise
        # lets Requests pre-read an unbounded body while preparing Response.next.
        return iter(())


def _get_with_budget(
    url: str,
    *,
    headers: Optional[dict] = None,
    timeout: int = 30,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    ca_bundle: Optional[str] = None,
    budget=None,
):
    if ca_bundle is not None and (not isinstance(ca_bundle, str) or not ca_bundle.strip()):
        raise ValueError("CA bundle must be a non-empty path")
    current_url = validate_outbound_url(url)
    with _OutboundSession() as session:
        session.trust_env = False
        session.verify = True if ca_bundle is None else ca_bundle
        for redirect_count in range(max_redirects + 1):
            budget.check()
            # Validate the same canonical URL Requests will actually send (IDNA,
            # escaping, and authority parsing), before resolving exactly once.
            current_url = validate_outbound_url(current_url)
            current_url = session.prepare_request(requests.Request("GET", current_url)).url
            current_url = validate_outbound_url(current_url)
            parsed = urllib.parse.urlsplit(current_url)
            addresses = _validated_addresses(parsed, budget)
            hop_headers = requests.structures.CaseInsensitiveDict(headers or {})
            hop_headers["Host"] = parsed.netloc.rsplit("@", 1)[-1]
            # Preserve the old per-hop requests.get cookie isolation.
            session.cookies.clear()
            with closing(_PinnedAdapter(current_url, addresses, budget)) as adapter:
                session.mount(parsed.scheme + "://", adapter)
                with closing(session.get(
                    current_url,
                    headers=hop_headers,
                    timeout=min(timeout, budget.remaining()),
                    allow_redirects=False,
                    stream=True,
                )) as response:
                    budget.check()
                    if response.status_code in REDIRECT_STATUSES:
                        location = response.headers.get("Location")
                        if not location:
                            raise UnsafeOutboundUrl("订阅重定向缺少目标地址")
                        if redirect_count >= max_redirects:
                            raise UnsafeOutboundUrl("订阅地址重定向次数过多")
                        current_url = urllib.parse.urljoin(current_url, location)
                        continue

                    content_length = response.headers.get("Content-Length")
                    if content_length:
                        try:
                            parsed_content_length = int(content_length)
                        except ValueError:
                            parsed_content_length = None
                        if parsed_content_length is not None and parsed_content_length > max_response_bytes:
                            raise ResponseTooLarge("订阅响应超过大小限制")

                    chunks = []
                    total = 0
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        budget.check()
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > max_response_bytes:
                            raise ResponseTooLarge("订阅响应超过大小限制")
                        chunks.append(chunk)
                    budget.check()
                    response._content = b"".join(chunks)
                    response._content_consumed = True
                    return response

    raise UnsafeOutboundUrl("订阅地址重定向次数过多")


def safe_get(
    url: str,
    *,
    headers: Optional[dict] = None,
    timeout: int = 30,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    ca_bundle: Optional[str] = None,
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
    deadline: Optional[float] = None,
    stop_event=None,
):
    timeout = _positive_seconds(timeout)
    with RequestBudget(total_timeout, deadline=deadline, stop_event=stop_event) as budget:
        try:
            return _get_with_budget(url, headers=headers, timeout=timeout,
                                    max_response_bytes=max_response_bytes, max_redirects=max_redirects,
                                    ca_bundle=ca_bundle, budget=budget)
        except Exception:
            # Socket shutdown may surface as EOF/ProtocolError/SSLError rather
            # than Timeout. Report the budget reason without leaking the URL.
            budget.check()
            raise
