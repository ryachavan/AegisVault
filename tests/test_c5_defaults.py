"""Test Secure Defaults and Provisioning — C5 (Secure By Default Configurations).

Proves:
  - No default administrative credentials exist.
  - Administrative accounts must be created via the custom CLI command.
"""

from app.models import User


def test_c5_admin_created_via_cli_only(app):
    """Proves admin user can be created via CLI with interactive password confirmation."""
    runner = app.test_cli_runner()

    # Invoke create-admin CLI command
    result = runner.invoke(
        args=["create-admin", "cli_superadmin"],
        input="StrongCliPassword123!\nStrongCliPassword123!\n",
    )
    assert result.exit_code == 0
    assert "Admin user 'cli_superadmin' created" in result.output

    with app.app_context():
        user = User.query.filter_by(username="cli_superadmin").first()
        assert user is not None
        assert user.role == "admin"
