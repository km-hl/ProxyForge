"""Outbound HTTP safeguards for user-configured subscription sources."""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import Iterable, Optional

import requests


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
    return {record[4][0] for record in records}


def _is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


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
    if literal_address is not None and not literal_address.is_global:
        raise UnsafeOutboundUrl("订阅地址不能指向私有或保留网络")

    if resolve_dns:
        port = parsed_port or (443 if parsed.scheme.lower() == "https" else 80)
        addresses = _resolved_addresses(hostname, port)
        if not addresses or any(not _is_public_address(item) for item in addresses):
            raise UnsafeOutboundUrl("订阅地址解析到了私有或保留网络")

    return urllib.parse.urlunsplit(parsed)


def safe_get(
    url: str,
    *,
    headers: Optional[dict] = None,
    timeout: int = 30,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
):
    current_url = validate_outbound_url(url)
    for redirect_count in range(max_redirects + 1):
        current_url = validate_outbound_url(current_url, resolve_dns=True)
        response = requests.get(
            current_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )

        if response.status_code in REDIRECT_STATUSES:
            location = response.headers.get("Location")
            response.close()
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
                response.close()
                raise ResponseTooLarge("订阅响应超过大小限制")

        chunks = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_response_bytes:
                    raise ResponseTooLarge("订阅响应超过大小限制")
                chunks.append(chunk)
            response._content = b"".join(chunks)
            response._content_consumed = True
        except Exception:
            response.close()
            raise
        response.close()
        return response

    raise UnsafeOutboundUrl("订阅地址重定向次数过多")
