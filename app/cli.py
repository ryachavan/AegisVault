"""CLI commands — C5 (Secure By Default Configurations).

Admin user is created via CLI only — no default credentials.
Provides administrative identity lifecycle and security operations via CLI.
"""

import os
import click
from flask import current_app
from app.extensions import db
from app.models import User, Note
from app.security.passwords import hash_password
from app.security.logging_setup import log_security_event


def register_cli(app):
    """Register custom CLI commands on *app*."""

    @app.cli.command("create-admin")
    @click.argument("username")
    @click.password_option(prompt="Password", confirmation_prompt=True)
    def create_admin(username, password):
        """Create a new root administrator account."""
        if User.query.filter_by(username=username).first():
            click.echo(f"Error: user '{username}' already exists.", err=True)
            raise SystemExit(1)
        if len(password) < 8:
            click.echo("Error: password must be at least 8 characters.", err=True)
            raise SystemExit(1)
        user = User(
            username=username,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        log_security_event("CLI_USER_CREATED", f"Admin user created via CLI username={username}")
        click.echo(f"[SUCCESS] Admin user '{username}' created successfully.")

    @app.cli.command("create-user")
    @click.argument("username")
    @click.password_option(prompt="Password", confirmation_prompt=True)
    def create_user(username, password):
        """Create a standard user account via CLI."""
        if User.query.filter_by(username=username).first():
            click.echo(f"Error: user '{username}' already exists.", err=True)
            raise SystemExit(1)
        if len(password) < 8:
            click.echo("Error: password must be at least 8 characters.", err=True)
            raise SystemExit(1)
        user = User(
            username=username,
            password_hash=hash_password(password),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        log_security_event("CLI_USER_CREATED", f"Standard user created via CLI username={username}")
        click.echo(f"[SUCCESS] User '{username}' created successfully.")

    @app.cli.command("reset-password")
    @click.argument("username")
    @click.password_option(prompt="New Password", confirmation_prompt=True)
    def reset_password(username, password):
        """Reset an operator's password securely via CLI."""
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f"Error: user '{username}' not found.", err=True)
            raise SystemExit(1)
        if len(password) < 8:
            click.echo("Error: password must be at least 8 characters.", err=True)
            raise SystemExit(1)
        user.password_hash = hash_password(password)
        db.session.commit()
        log_security_event("CLI_PASSWORD_RESET", f"Password reset via CLI username={username}")
        click.echo(f"[SUCCESS] Password for user '{username}' has been successfully reset.")

    @app.cli.command("list-users")
    def list_users():
        """List all registered users, roles, and status."""
        users = User.query.order_by(User.id.asc()).all()
        if not users:
            click.echo("No users registered.")
            return

        click.echo("-" * 65)
        click.echo(f"{'ID':<6} {'USERNAME':<20} {'ROLE':<10} {'ACTIVE':<10} {'REGISTERED UTC':<18}")
        click.echo("-" * 65)
        for u in users:
            active_str = "YES" if u.is_active else "DISABLED"
            created_str = u.created_at.strftime("%Y-%m-%d %H:%M") if u.created_at else "N/A"
            click.echo(f"#{u.id:<5} {u.username:<20} {u.role:<10} {active_str:<10} {created_str:<18}")
        click.echo("-" * 65)
        click.echo(f"Total users: {len(users)}")

    @app.cli.command("change-role")
    @click.argument("username")
    @click.argument("new_role", type=click.Choice(["user", "admin"], case_sensitive=False))
    def change_role(username, new_role):
        """Change a user's role (promote to admin or demote to user)."""
        new_role = new_role.lower()
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f"Error: user '{username}' not found.", err=True)
            raise SystemExit(1)

        if user.role == "admin" and new_role != "admin":
            admin_count = User.query.filter_by(role="admin").count()
            if admin_count <= 1:
                click.echo("Error: Cannot demote the last remaining administrator.", err=True)
                raise SystemExit(1)

        old_role = user.role
        user.role = new_role
        db.session.commit()
        log_security_event(
            "CLI_ROLE_CHANGED",
            f"Role for {username} changed from {old_role} to {new_role} via CLI"
        )
        click.echo(f"[SUCCESS] User '{username}' role updated: {old_role} -> {new_role}.")

    @app.cli.command("deactivate-user")
    @click.argument("username")
    def deactivate_user(username):
        """Deactivate a user account (prevents login without deleting data)."""
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f"Error: user '{username}' not found.", err=True)
            raise SystemExit(1)

        if user.role == "admin":
            admin_count = User.query.filter_by(role="admin", is_active=True).count()
            if admin_count <= 1:
                click.echo("Error: Cannot deactivate the last active administrator.", err=True)
                raise SystemExit(1)

        user.is_active = False
        db.session.commit()
        log_security_event("CLI_USER_DEACTIVATED", f"User {username} deactivated via CLI")
        click.echo(f"[SUCCESS] User '{username}' has been deactivated.")

    @app.cli.command("activate-user")
    @click.argument("username")
    def activate_user(username):
        """Reactivate a previously deactivated user account."""
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f"Error: user '{username}' not found.", err=True)
            raise SystemExit(1)

        user.is_active = True
        db.session.commit()
        log_security_event("CLI_USER_ACTIVATED", f"User {username} activated via CLI")
        click.echo(f"[SUCCESS] User '{username}' has been activated.")

    @app.cli.command("delete-user")
    @click.argument("username")
    @click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
    def delete_user(username, yes):
        """Permanently delete a user and their vault records."""
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f"Error: user '{username}' not found.", err=True)
            raise SystemExit(1)

        if user.role == "admin":
            admin_count = User.query.filter_by(role="admin").count()
            if admin_count <= 1:
                click.echo("Error: Cannot delete the last remaining administrator.", err=True)
                raise SystemExit(1)

        if not yes:
            if not click.confirm(f"Are you sure you want to permanently delete user '{username}' and all their records?"):
                click.echo("Operation cancelled.")
                return

        db.session.delete(user)
        db.session.commit()
        log_security_event("CLI_USER_DELETED", f"User {username} deleted via CLI")
        click.echo(f"[SUCCESS] User '{username}' and associated records have been deleted.")

    @app.cli.command("view-logs")
    @click.option("--limit", default=25, show_default=True, help="Number of latest log lines to view.")
    def view_logs(limit):
        """Inspect recent SIEM security audit log entries."""
        log_path = os.path.join(current_app.root_path, "..", "logs", "security.log")
        if not os.path.exists(log_path):
            click.echo("Security log file does not exist yet.")
            return

        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip()]

        recent = lines[-limit:]
        click.echo("=" * 70)
        click.echo(f"AEGISVAULT // SIEM AUDIT TRAIL (LATEST {len(recent)} EVENTS)")
        click.echo("=" * 70)
        for line in reversed(recent):
            click.echo(line)
        click.echo("=" * 70)
