"""Test Access Control boundaries — C1 (Implement Access Control).

Proves:
  - Deny-by-default on unauthenticated requests.
  - Ownership boundaries: User A cannot read, edit, or delete User B's note.
  - Non-existence parity: 404 returned for unowned notes (no leak of existence).
  - Privilege boundaries: @role_required("admin") blocks non-admins (403).
  - Last admin preservation: cannot demote the only remaining administrator.
"""

from app.extensions import db
from app.models import Note, User


def test_c1_deny_by_default_requires_login(client):
    """Proves unauthenticated requests to protected endpoints redirect to login, while home is public."""
    # Home page is public
    home_resp = client.get("/")
    assert home_resp.status_code == 200

    # Protected endpoints enforce deny-by-default
    endpoints = ["/notes/", "/notes/create", "/admin/users", "/admin/logs"]
    for ep in endpoints:
        resp = client.get(ep)
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]


def test_c1_user_cannot_read_another_users_note(client, alice_user, bob_user, alice_note):
    """Proves User B cannot view User A's note and gets 404 (does not leak existence)."""
    # Log in as Bob
    client.post(
        "/auth/login",
        data={"username": "bob", "password": "BobSecretPass123!"},
        follow_redirects=True,
    )

    # Bob attempts to view Alice's note
    resp = client.get(f"/notes/{alice_note}")
    assert resp.status_code == 404
    assert b"Alice Confidential Research" not in resp.data

    # A non-existent note returns the exact same 404 status (no ID enumeration)
    resp_nonexistent = client.get("/notes/999999")
    assert resp_nonexistent.status_code == 404


def test_c1_user_cannot_edit_another_users_note(client, alice_user, bob_user, alice_note):
    """Proves User B cannot edit or overwrite User A's note."""
    client.post(
        "/auth/login",
        data={"username": "bob", "password": "BobSecretPass123!"},
        follow_redirects=True,
    )

    # GET edit form
    resp = client.get(f"/notes/{alice_note}/edit")
    assert resp.status_code == 404

    # POST edit modification
    resp = client.post(
        f"/notes/{alice_note}/edit",
        data={"title": "Bob Tampered Title", "content": "Tampered"},
        follow_redirects=True,
    )
    assert resp.status_code == 404

    # Verify original note remains unchanged in database
    note = db.session.get(Note, alice_note)
    assert note.title == "Alice Confidential Research"


def test_c1_user_cannot_delete_another_users_note(client, alice_user, bob_user, alice_note):
    """Proves User B cannot delete User A's note."""
    client.post(
        "/auth/login",
        data={"username": "bob", "password": "BobSecretPass123!"},
        follow_redirects=True,
    )

    resp = client.post(f"/notes/{alice_note}/delete", follow_redirects=True)
    assert resp.status_code == 404

    # Verify note still exists in database
    note = db.session.get(Note, alice_note)
    assert note is not None


def test_c1_non_admin_cannot_access_admin_routes(client, alice_user):
    """Proves standard user cannot access administrative controls (returns 403)."""
    client.post(
        "/auth/login",
        data={"username": "alice", "password": "AliceSecretPass123!"},
        follow_redirects=True,
    )

    resp = client.get("/admin/users")
    assert resp.status_code == 403
    assert b"403" in resp.data

    resp = client.get("/admin/logs")
    assert resp.status_code == 403


def test_c1_admin_can_access_admin_routes(client, admin_user):
    """Proves admin user can access administrative controls."""
    client.post(
        "/auth/login",
        data={"username": "secadmin", "password": "AdminSecretPass123!"},
        follow_redirects=True,
    )

    resp = client.get("/admin/users")
    assert resp.status_code == 200
    assert b"SOC DIRECTORY" in resp.data

    resp = client.get("/admin/logs")
    assert resp.status_code == 200
    assert b"SIEM AUDIT TRAIL" in resp.data


def test_c1_cannot_remove_last_admin(client, admin_user):
    """Proves application prevents demoting the last remaining administrator."""
    client.post(
        "/auth/login",
        data={"username": "secadmin", "password": "AdminSecretPass123!"},
        follow_redirects=True,
    )

    resp = client.post(
        "/admin/users/change-role",
        data={"user_id": str(admin_user), "role": "user"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Cannot remove the last remaining admin" in resp.data

    # Verify user remains an admin
    admin = db.session.get(User, admin_user)
    assert admin.role == "admin"
