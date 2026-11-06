"""Access-control decorators — C1 (Implement Access Control).

@role_required(role)  — deny unless current_user.role matches.
@owner_required       — deny (404) unless the note belongs to current_user.
                        Returns 404 for both missing and unowned notes so that
                        a note's existence is never revealed to non-owners.
"""

from functools import wraps

from flask import abort
from flask_login import current_user

from app.extensions import db
from app.models import Note


def role_required(role):
    """Decorator: abort 403 unless current_user.role == *role*."""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def owner_required(f):
    """Decorator: look up ``note_id`` from the URL, verify ownership.

    * Note found and owned → passes ``note=<Note>`` to the view.
    * Note missing or unowned → 404 (never reveals existence).
    """

    @wraps(f)
    def decorated_function(note_id, *args, **kwargs):
        note = db.session.get(Note, note_id)
        # C1: identical response for "not found" and "not yours"
        if note is None or note.user_id != current_user.id:
            abort(404)
        return f(note=note, *args, **kwargs)

    return decorated_function
