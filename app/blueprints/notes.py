"""Notes blueprint — CRUD notes and link preview.

Controls:
  C1  Implement Access Control              — @owner_required on all note-specific routes,
                                              queries filtered by current_user.id
  C3  Validate all Input & Handle Exceptions— WTForms validation, ORM-only queries,
                                              Jinja autoescaping
  C8  Leverage Browser Security Features    — CSRF token on all forms, POST-only deletes
  C10 Stop Server Side Request Forgery      — safe_fetch_url for link preview
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Optional, URL

from app.extensions import db
from app.models import Note
from app.security.decorators import owner_required
from app.security.ssrf import SafeFetchError, safe_fetch_url

notes_bp = Blueprint("notes", __name__, url_prefix="/notes")


# ── Forms (C3, C8) ────────────────────────────────────────────────
class NoteForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(min=1, max=200)])
    content = TextAreaField("Content", validators=[Optional(), Length(max=10000)])
    url = StringField("Link URL (optional)", validators=[Optional(), Length(max=2048)])
    submit = SubmitField("Save Note")


class DeleteForm(FlaskForm):
    """CSRF-protected form for note deletion (C8: no GET deletes)."""
    submit = SubmitField("Delete")


# ── Routes ────────────────────────────────────────────────────────
@notes_bp.route("/", methods=["GET"])
def list_notes():
    """List notes for current user only (C1: ownership boundary)."""
    notes = (
        Note.query.filter_by(user_id=current_user.id)
        .order_by(Note.created_at.desc())
        .all()
    )
    return render_template("notes/list.html", notes=notes)


@notes_bp.route("/create", methods=["GET", "POST"])
def create_note():
    form = NoteForm()
    if form.validate_on_submit():
        url_val = form.url.data.strip() if form.url.data else None
        url_title = None
        url_description = None

        if url_val:
            try:
                # C10: SSRF-safe preview fetch
                preview = safe_fetch_url(url_val)
                url_title = preview.title
                url_description = preview.description
            except SafeFetchError as exc:
                flash(f"Link preview failed: {exc}", "warning")

        note = Note(
            title=form.title.data.strip(),
            content=form.content.data or "",
            url=url_val,
            url_title=url_title,
            url_description=url_description,
            user_id=current_user.id,
        )
        db.session.add(note)
        db.session.commit()
        flash("Note created successfully.", "success")
        return redirect(url_for("notes.view_note", note_id=note.id))

    return render_template("notes/create.html", form=form)


@notes_bp.route("/<int:note_id>", methods=["GET"])
@owner_required
def view_note(note: Note):
    """View note. C1: owner_required aborts 404 if not found or not owner."""
    delete_form = DeleteForm()
    return render_template("notes/view.html", note=note, delete_form=delete_form)


@notes_bp.route("/<int:note_id>/edit", methods=["GET", "POST"])
@owner_required
def edit_note(note: Note):
    """Edit note. C1: owner_required aborts 404 if not found or not owner."""
    form = NoteForm(obj=note)
    if form.validate_on_submit():
        url_val = form.url.data.strip() if form.url.data else None
        
        # If URL changed, re-fetch preview safely
        if url_val != note.url:
            note.url = url_val
            note.url_title = None
            note.url_description = None
            if url_val:
                try:
                    preview = safe_fetch_url(url_val)
                    note.url_title = preview.title
                    note.url_description = preview.description
                except SafeFetchError as exc:
                    flash(f"Link preview failed: {exc}", "warning")
        
        note.title = form.title.data.strip()
        note.content = form.content.data or ""
        db.session.commit()
        flash("Note updated successfully.", "success")
        return redirect(url_for("notes.view_note", note_id=note.id))

    return render_template("notes/edit.html", form=form, note=note)


@notes_bp.route("/<int:note_id>/delete", methods=["POST"])
@owner_required
def delete_note(note: Note):
    """Delete note. C1: owner_required, C8: POST with CSRF only."""
    form = DeleteForm()
    if form.validate_on_submit():
        db.session.delete(note)
        db.session.commit()
        flash("Note deleted.", "info")
    return redirect(url_for("notes.list_notes"))
