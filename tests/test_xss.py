"""Test Cross-Site Scripting (XSS) neutralization.

Controls:
  C3  Validate all Input & Handle Exceptions — Jinja2 autoescaping
  C8  Leverage Browser Security Features     — Strict CSP without unsafe-inline
"""

from app.models import Note


def test_c3_xss_script_tags_escaped_in_note_view(client, alice_user):
    """Proves script tags in note content and title are HTML-escaped on inspection."""
    client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
        follow_redirects=True,
    )

    xss_payload = "<script>alert('XSS_ATTACK_VECTOR')</script>"
    resp = client.post(
        "/notes/create",
        data={
            "title": f"XSS Title {xss_payload}",
            "content": f"Payload Body: {xss_payload}",
            "url": "",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200

    # Ensure unescaped raw script tag is NEVER rendered in the HTML
    assert b"<script>alert('XSS_ATTACK_VECTOR')</script>" not in resp.data
    # Ensure escaped HTML entities are present
    assert b"&lt;script&gt;alert(&#39;XSS_ATTACK_VECTOR&#39;)&lt;/script&gt;" in resp.data or \
           b"&lt;script&gt;alert('XSS_ATTACK_VECTOR')&lt;/script&gt;" in resp.data


def test_c3_xss_script_tags_escaped_in_note_list(client, alice_user):
    """Proves note list template autoescapes titles containing XSS vectors."""
    client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
        follow_redirects=True,
    )

    img_onerror = "<img src=x onerror=alert(document.cookie)>"
    client.post(
        "/notes/create",
        data={"title": img_onerror, "content": "Safe content", "url": ""},
        follow_redirects=True,
    )

    resp = client.get("/notes/")
    assert resp.status_code == 200
    # Must be escaped, never executed as raw HTML tag
    assert b"<img src=x onerror=alert(document.cookie)>" not in resp.data
    assert b"&lt;img src=x onerror=alert(document.cookie)&gt;" in resp.data or \
           b"&lt;img" in resp.data


def test_c8_csp_header_blocks_inline_scripts(client):
    """Proves CSP header forbids unsafe-inline and restricts script execution to self."""
    resp = client.get("/auth/login")
    assert resp.status_code == 200
    csp = resp.headers.get("Content-Security-Policy", "")

    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
