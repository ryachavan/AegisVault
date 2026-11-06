"""Test Server-Side Request Forgery (SSRF) protections — C10 (Stop Server Side Request Forgery).

Proves that:
  - 127.0.0.1, ::1, localhost, 169.254.169.254, 10.x, 192.168.x are blocked.
  - Non-HTTP schemes (ftp, file, gopher) are rejected.
  - HTTP redirects are blocked (no redirect chasing).
  - DNS pinning prevents DNS-rebinding attacks.
  - Response size cap (1 MB) is enforced.
"""

from unittest.mock import MagicMock, patch
import pytest

from app.security.ssrf import SafeFetchError, safe_fetch_url


def test_c10_blocks_loopback_ipv4():
    """Proves IPv4 loopback (127.0.0.1) is rejected."""
    with pytest.raises(SafeFetchError, match="loopback"):
        safe_fetch_url("http://127.0.0.1/admin")


def test_c10_blocks_loopback_ipv6():
    """Proves IPv6 loopback (::1) is rejected."""
    with pytest.raises(SafeFetchError, match="loopback"):
        safe_fetch_url("http://[::1]/secret")


def test_c10_blocks_localhost_hostname():
    """Proves localhost domain resolving to loopback is rejected."""
    with pytest.raises(SafeFetchError, match="loopback"):
        safe_fetch_url("http://localhost:5000/internal")


def test_c10_blocks_cloud_metadata_ip():
    """Proves cloud instance metadata IP (169.254.169.254) is rejected."""
    with pytest.raises(SafeFetchError, match="link-local"):
        safe_fetch_url("http://169.254.169.254/latest/meta-data/")


def test_c10_blocks_private_network_10_x():
    """Proves RFC 1918 Class A private IP (10.x.x.x) is rejected."""
    with pytest.raises(SafeFetchError, match="private"):
        safe_fetch_url("http://10.0.0.1/intranet")


def test_c10_blocks_private_network_192_168_x():
    """Proves RFC 1918 Class C private IP (192.168.x.x) is rejected."""
    with pytest.raises(SafeFetchError, match="private"):
        safe_fetch_url("http://192.168.1.1/router")


def test_c10_blocks_non_http_schemes():
    """Proves non-http/https schemes are rejected immediately."""
    invalid_schemes = [
        "file:///etc/passwd",
        "file://C:/Windows/win.ini",
        "ftp://ftp.internal.lan/backup.zip",
        "gopher://127.0.0.1:70/",
        "dict://127.0.0.1:11211/",
    ]
    for url in invalid_schemes:
        with pytest.raises(SafeFetchError, match="Only http and https"):
            safe_fetch_url(url)


def test_c10_blocks_redirects():
    """Proves HTTP redirects (301, 302, 307) are rejected without following."""
    mock_resp = MagicMock()
    mock_resp.is_redirect = True
    mock_resp.headers = {"Location": "http://127.0.0.1/admin"}

    with patch("app.security.ssrf._resolve_and_validate", return_value=("93.184.216.34", None)):
        with patch("requests.Session.get", return_value=mock_resp):
            with pytest.raises(SafeFetchError, match="Redirects are not allowed"):
                safe_fetch_url("http://external-redirector.com/link")


def test_c10_enforces_size_cap():
    """Proves streaming response exceeding 1 MB triggers size limit error."""
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_resp.is_permanent_redirect = False
    mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
    # Stream chunks exceeding 1 MB
    mock_resp.iter_content = MagicMock(return_value=[b"A" * 65536] * 20)

    with patch("app.security.ssrf._resolve_and_validate", return_value=("93.184.216.34", None)):
        with patch("requests.Session.get", return_value=mock_resp):
            with pytest.raises(SafeFetchError, match="byte limit"):
                safe_fetch_url("http://legit-site.com/huge.html")


def test_c10_dns_pinning_prevents_rebinding():
    """Proves socket resolution is pinned to the validated IP during request."""
    import socket
    from app.security.ssrf import _forced_ip_resolution, _dns_lock

    target_host = "legit-site.com"
    pinned_ip = "93.184.216.34"

    with _dns_lock, _forced_ip_resolution(target_host, pinned_ip):
        res = socket.getaddrinfo(target_host, 80)
        resolved_ip = res[0][4][0]
        assert resolved_ip == pinned_ip
