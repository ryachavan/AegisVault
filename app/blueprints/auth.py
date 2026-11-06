"""Auth blueprint — register / login / logout.

Controls:
  C1  Implement Access Control              — auth routes exempt from deny-by-default
  C2  Use Cryptography to Protect Data      — Argon2 hash + verify-and-rehash
  C3  Validate all Input & Handle Exceptions— WTForms validation
  C7  Secure Digital Identities             — rate limit, session regen, generic errors
  C9  Implement Security Logging            — login success / fail / logout events
"""

from urllib.parse import urlparse

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp

from app.extensions import db, limiter
from app.models import User
from app.security.logging_setup import log_security_event
from app.security.passwords import hash_password, verify_and_rehash

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ── Forms (C3: WTForms validation) ────────────────────────────────
class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=80),
            Regexp(r"^[a-zA-Z0-9_]+$", message="Letters, digits, and underscores only."),
        ],
    )
    password = PasswordField(
        "Password", validators=[DataRequired(), Length(min=8, max=128)]
    )
    confirm = PasswordField(
        "Confirm password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=1, max=80)]
    )
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


# ── Routes ────────────────────────────────────────────────────────
@auth_bp.before_request
def _redirect_if_authenticated():
    """Prevent logged-in users from accessing login or registration pages."""
    if current_user.is_authenticated and request.endpoint in ("auth.login", "auth.register"):
        return redirect(url_for("notes.list_notes"))


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])  # C7: rate-limit registration attempts
def register():
    if current_user.is_authenticated:
        return redirect(url_for("notes.list_notes"))

    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already taken.", "danger")
            return render_template("auth/register.html", form=form)

        user = User(
            username=form.username.data,
            password_hash=hash_password(form.password.data),
        )
        db.session.add(user)
        db.session.commit()
        flash("Account created — please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])  # C7: rate-limit login attempts
def login():
    if current_user.is_authenticated:
        return redirect(url_for("notes.list_notes"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user is None:
            # C7: generic message — never reveal whether the username exists
            log_security_event(
                "LOGIN_FAILED", "Invalid credentials",
                username=form.username.data, ip=request.remote_addr,
            )
            flash("Invalid credentials.", "danger")
            return render_template("auth/login.html", form=form)

        valid, new_hash = verify_and_rehash(user.password_hash, form.password.data)

        if not valid:
            log_security_event(
                "LOGIN_FAILED", "Invalid credentials",
                username=form.username.data, ip=request.remote_addr,
            )
            flash("Invalid credentials.", "danger")
            return render_template("auth/login.html", form=form)

        # C2: transparently rehash if Argon2 parameters changed
        if new_hash:
            user.password_hash = new_hash
            db.session.commit()

        # C7: regenerate session on login
        session.clear()
        login_user(user, remember=False)
        session.permanent = True

        log_security_event(
            "LOGIN_SUCCESS", "User logged in",
            username=user.username, ip=request.remote_addr,
        )

        # Safe redirect — reject absolute / external URLs
        next_page = request.args.get("next")
        if next_page:
            parsed = urlparse(next_page)
            if parsed.netloc or parsed.scheme or next_page.startswith("//"):
                next_page = None
        return redirect(next_page or url_for("notes.list_notes"))

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
def logout():
    if current_user.is_authenticated:
        log_security_event(
            "LOGOUT", "User logged out",
            username=current_user.username, ip=request.remote_addr,
        )
        logout_user()
    session.clear()  # C7: clear session fully on logout
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
