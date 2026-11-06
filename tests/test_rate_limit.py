"""Test authentication rate limiting — C7 (Secure Digital Identities).

Proves that repeated authentication attempts trigger 429 Too Many Requests
to mitigate brute-force and credential stuffing attacks.
"""

from app.extensions import limiter


def test_c7_login_rate_limit_triggers(client, alice_user):
    """Proves that exceeding 5 POST login attempts within a minute triggers 429."""
    # First 5 login attempts receive normal 200 responses
    for i in range(5):
        resp = client.post(
            "/auth/login",
            data={"username": "alice", "password": f"WrongAttempt{i}"},
        )
        assert resp.status_code == 200, f"Attempt {i+1} should be processed"

    # 6th attempt within the same minute must be rate limited (429)
    resp = client.post(
        "/auth/login",
        data={"username": "alice", "password": "WrongAttempt6"},
    )
    assert resp.status_code == 429


def test_c7_register_rate_limit_triggers(client):
    """Proves that registration attempts are capped at 5 per minute (429 on 6th)."""
    for i in range(5):
        resp = client.post(
            "/auth/register",
            data={
                "username": f"user_rl_{i}",
                "password": "Password123!",
                "confirm": "Password123!",
            },
        )
        assert resp.status_code in (200, 302)

    # 6th attempt must be rate limited
    resp = client.post(
        "/auth/register",
        data={
            "username": "user_rl_overflow",
            "password": "Password123!",
            "confirm": "Password123!",
        },
    )
    assert resp.status_code == 429
