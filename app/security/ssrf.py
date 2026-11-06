"""SSRF-safe URL fetcher — C10 (Stop Server Side Request Forgery).

Fetches the ``<title>`` and ``<meta name="description">`` from a remote URL
while enforcing:

  1. http / https schemes only.
  2. DNS resolution with *every* returned IP checked against block-lists
     (loopback, private, link-local, reserved, multicast, unspecified).
  3. Connection to the vetted IP (not the hostname) to prevent DNS rebinding.
  4. ``allow_redirects=False`` — no server-controlled redirect chains.
  5. 5-second timeout.
  6. 1 MB response-size cap (streamed).
  7. ``Content-Type`` must contain ``text/html``.
  8. Only the ``<title>`` and ``<meta name="description">`` are parsed.
  9. Every blocked attempt is logged to the ``security`` logger (C9).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from contextlib import contextmanager
from html.parser import HTMLParser
from typing import NamedTuple
from urllib.parse import urlparse

import requests

security_log = logging.getLogger("security")

# ── Tunables ──────────────────────────────────────────────────────
MAX_RESPONSE_BYTES = 1_048_576  # 1 MB
TIMEOUT_SECONDS = 5
ALLOWED_SCHEMES = frozenset({"http", "https"})

# Thread lock for the DNS-pinning context manager (monkey-patches socket)
_dns_lock = threading.Lock()


# ── Public types ──────────────────────────────────────────────────
class LinkPreview(NamedTuple):
    title: str | None
    description: str | None


class SafeFetchError(Exception):
    """Raised when a URL is blocked or cannot be fetched safely."""


# ── IP checks ─────────────────────────────────────────────────────
def _is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if *ip* must NOT be contacted by the server."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_and_validate(hostname: str) -> tuple[str, None] | tuple[None, str]:
    """Resolve *hostname* and verify every IP is safe.

    Returns ``(first_safe_ip, None)`` on success or ``(None, reason)`` on
    failure.
    """
    try:
        addrinfos = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        return None, f"DNS resolution failed: {exc}"

    if not addrinfos:
        return None, "DNS returned no results"

    ips: set[str] = set()
    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        ips.add(sockaddr[0])

    for ip_str in ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None, f"Unparseable IP from DNS: {ip_str}"
        if _is_ip_blocked(ip_obj):
            return None, f"Blocked IP {ip_str} ({_block_reason(ip_obj)})"

    # Return the first IP for connection pinning
    return next(iter(ips)), None


def _block_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Human-readable reason an IP was blocked (for logs)."""
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    return "blocked"


# ── DNS pinning ───────────────────────────────────────────────────
@contextmanager
def _forced_ip_resolution(hostname: str, vetted_ip: str):
    """Temporarily patch ``socket.getaddrinfo`` so *hostname* resolves only
    to *vetted_ip*.  This prevents DNS-rebinding between validation and
    connection.  Must be used under ``_dns_lock``.
    """
    _orig = socket.getaddrinfo

    def _patched(host, port, family=0, type_=0, proto=0, flags=0):
        if host == hostname:
            if ":" in vetted_ip:  # IPv6
                return [
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, "",
                     (vetted_ip, port or 0, 0, 0))
                ]
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (vetted_ip, port or 0))
            ]
        return _orig(host, port, family, type_, proto, flags)

    socket.getaddrinfo = _patched  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = _orig  # type: ignore[assignment]


# ── HTML title parser ─────────────────────────────────────────────
class _TitleParser(HTMLParser):
    """Minimal parser: extracts ``<title>`` text and
    ``<meta name="description" content="...">``."""

    def __init__(self):
        super().__init__()
        self._in_title = False
        self.title: str | None = None
        self.description: str | None = None

    # --- callbacks ---------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            attr_map = {k.lower(): v for k, v in attrs}
            if attr_map.get("name", "").lower() == "description":
                self.description = attr_map.get("content")

    def handle_data(self, data: str):
        if self._in_title:
            self.title = (self.title or "") + data

    def handle_endtag(self, tag: str):
        if tag == "title":
            self._in_title = False
            if self.title:
                self.title = self.title.strip()


# ── Public API ────────────────────────────────────────────────────
def safe_fetch_url(url: str) -> LinkPreview:
    """Fetch *url* safely and return a ``LinkPreview``.

    Raises ``SafeFetchError`` if the URL is blocked or unfetchable.
    Every block is logged to the ``security`` logger.
    """
    # 1. Scheme check
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        _log_blocked(url, f"Disallowed scheme: {parsed.scheme}")
        raise SafeFetchError(f"Only http and https URLs are allowed")

    hostname = parsed.hostname
    if not hostname:
        _log_blocked(url, "No hostname")
        raise SafeFetchError("URL has no hostname")

    # 2. Resolve & validate every IP
    safe_ip, reason = _resolve_and_validate(hostname)
    if reason:
        _log_blocked(url, reason)
        raise SafeFetchError(reason)

    assert safe_ip is not None  # mypy

    # 3. Fetch with DNS pinned to vetted IP
    try:
        with _dns_lock, _forced_ip_resolution(hostname, safe_ip):
            session = requests.Session()
            resp = session.get(
                url,
                allow_redirects=False,  # C10: no redirects
                timeout=TIMEOUT_SECONDS,
                stream=True,
                headers={"User-Agent": "secure-notes-link-preview/1.0"},
            )
    except requests.RequestException as exc:
        _log_blocked(url, f"Request error: {exc}")
        raise SafeFetchError(f"Request failed: {exc}") from exc

    # 4. Reject redirects explicitly (belt-and-suspenders)
    if resp.is_redirect or resp.is_permanent_redirect:
        _log_blocked(url, f"Redirect to {resp.headers.get('Location', '?')}")
        raise SafeFetchError("Redirects are not allowed")

    # 5. Content-Type check
    content_type = resp.headers.get("Content-Type", "")
    if "text/html" not in content_type.lower():
        raise SafeFetchError(f"Non-HTML content type: {content_type}")

    # 6. Size-capped streaming read
    chunks: list[bytes] = []
    size = 0
    for chunk in resp.iter_content(chunk_size=8192):
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise SafeFetchError(
                f"Response exceeds {MAX_RESPONSE_BYTES} byte limit"
            )
        chunks.append(chunk)

    # 7. Parse title / description
    html = b"".join(chunks).decode("utf-8", errors="replace")
    parser = _TitleParser()
    parser.feed(html)

    return LinkPreview(title=parser.title, description=parser.description)


# ── Internal helpers ──────────────────────────────────────────────
def _log_blocked(url: str, reason: str) -> None:
    """C9: log every blocked SSRF attempt."""
    security_log.warning("[SSRF_BLOCKED] url=%s reason=%s", url, reason)
