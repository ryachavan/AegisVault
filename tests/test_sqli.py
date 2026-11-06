"""Test SQL Injection neutralization — C3 (Validate all Input & Handle Exceptions).

Proves that SQLi payloads injected into authentication and note endpoints
are treated strictly as literal data by SQLAlchemy ORM and never executed.
"""

from app.extensions import db
from app.models import Note, User


def test_c3_sqli_payload_in_login_neutralised(client, alice_user):
    """Proves authentication cannot be bypassed using classic SQLi payloads."""
    sqli_payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin' --",
        "' UNION SELECT 1, 'admin', 'hash', 'admin', 1, 'now' --",
        "\" OR \"\"=\"",
        "') OR ('1'='1",
    ]

    from app.extensions import limiter

    for payload in sqli_payloads:
        limiter.reset()
        resp = client.post(
            "/auth/login",
            data={"username": payload, "password": "any_password"},
            follow_redirects=True,
        )
        # Authentication must fail safely; no user logged in
        assert resp.status_code == 200
        assert b"Invalid credentials" in resp.data
        assert b"VAULT RECORDS" not in resp.data


def test_c3_sqli_payload_in_note_creation_neutralised(client, alice_user):
    """Proves SQLi payloads in note fields are stored as literal strings without executing SQL."""
    # Authenticate as alice
    client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
        follow_redirects=True,
    )

    destructive_payload = "'; DROP TABLE notes; --"
    resp = client.post(
        "/notes/create",
        data={
            "title": destructive_payload,
            "content": "Testing ORM query parameterization: ' OR 1=1;",
            "url": "",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200

    # Verify notes table was NOT dropped and note was stored literally
    note = Note.query.filter_by(title=destructive_payload).first()
    assert note is not None
    assert note.title == destructive_payload
    assert "DROP TABLE" in note.title

    # Verify table is intact and readable
    assert Note.query.count() >= 1


def test_c3_sqli_in_note_lookup_neutralised(client, alice_user, alice_note):
    """Proves URL route constraints and ORM parameter binding neutralize SQLi."""
    client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
        follow_redirects=True,
    )

    # Route requires <int:note_id> — non-integer string SQLi returns 404 at router
    resp = client.get("/notes/1%20OR%201=1")
    assert resp.status_code == 404

    # Direct ORM session lookup handles string IDs safely via parameterization
    result = Note.query.filter(Note.id == "1 OR 1=1").first()
    assert result is None  # Does not evaluate as SQL or return note 1
