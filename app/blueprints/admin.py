"""Admin blueprint — user management and security log viewer.

Controls:
  C1  Implement Access Control              — @role_required("admin") on every route,
                                              cannot remove the last admin
  C8  Leverage Browser Security Features    — CSRF on role change form
  C9  Implement Security Logging & Mon.     — role changes logged, log viewer page
"""

import os
from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import HiddenField, SelectField, SubmitField
from wtforms.validators import DataRequired, AnyOf

from app.extensions import db
from app.models import User
from app.security.decorators import role_required
from app.security.logging_setup import log_security_event

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


class RoleChangeForm(FlaskForm):
    """CSRF-protected form for role changes (C8)."""
    user_id = HiddenField("User ID", validators=[DataRequired()])
    role = SelectField(
        "Role",
        choices=[("user", "User"), ("admin", "Admin")],
        validators=[DataRequired(), AnyOf(["user", "admin"])],
    )
    submit = SubmitField("Update Role")


@admin_bp.route("/users", methods=["GET"])
@role_required("admin")
def list_users():
    """List all users with role-change forms."""
    users = User.query.order_by(User.id.asc()).all()
    form = RoleChangeForm()
    return render_template("admin/users.html", users=users, form=form)


@admin_bp.route("/users/change-role", methods=["POST"])
@role_required("admin")
def change_role():
    """Change a user's role.

    C1: Cannot demote the last remaining admin.
    C9: Every role change is logged to security log.
    """
    form = RoleChangeForm()
    if form.validate_on_submit():
        user = db.session.get(User, int(form.user_id.data))
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("admin.list_users"))

        new_role = form.role.data
        old_role = user.role

        if old_role == new_role:
            flash(f"User {user.username} already has role {new_role}.", "info")
            return redirect(url_for("admin.list_users"))

        # C1: Do not allow removing the last admin
        if old_role == "admin" and new_role != "admin":
            admin_count = User.query.filter_by(role="admin").count()
            if admin_count <= 1:
                flash("Cannot remove the last remaining admin.", "danger")
                return redirect(url_for("admin.list_users"))

        user.role = new_role
        db.session.commit()

        # C9: Log role change
        log_security_event(
            "ROLE_CHANGED",
            f"Role for {user.username} changed from {old_role} to {new_role}",
            admin=current_user.username,
            target_user=user.username,
            old_role=old_role,
            new_role=new_role,
            ip=request.remote_addr,
        )
        flash(f"Updated role for {user.username} to {new_role}.", "success")
    else:
        flash("Invalid role change request.", "danger")

    return redirect(url_for("admin.list_users"))


@admin_bp.route("/logs", methods=["GET"])
@role_required("admin")
def view_log():
    """View security log (C9)."""
    log_file = current_app.config.get("SECURITY_LOG_FILE", "logs/security.log")
    log_lines = []
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                log_lines = f.readlines()
        except OSError as e:
            log_lines = [f"Error reading log file: {e}"]
    else:
        log_lines = ["Log file does not exist yet."]

    # Show newest entries at the top (reversed)
    recent_lines = log_lines[-500:]
    recent_lines.reverse()
    return render_template("admin/log.html", log_lines=recent_lines)
