"""Rotating security log — C9 (Implement Security Logging and Monitoring).

Sets up a ``RotatingFileHandler`` on the ``security`` logger and provides
``log_security_event()`` for structured event recording.

Logged events (written by blueprints / decorators):
  LOGIN_SUCCESS   — successful authentication
  LOGIN_FAILED    — wrong credentials (never logs which field was wrong)
  LOGOUT          — user logged out
  ACCESS_DENIED   — role or ownership check failed
  SSRF_BLOCKED    — link-preview URL rejected  (logged by ssrf.py directly)
  ROLE_CHANGED    — admin changed a user's role
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask


def setup_logging(app: Flask) -> None:
    """Attach a rotating file handler to the ``security`` logger."""
    log_file: str = app.config.get("SECURITY_LOG_FILE", "logs/security.log")
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    handler = RotatingFileHandler(
        log_file,
        maxBytes=1_048_576,   # 1 MB per file
        backupCount=5,
    )
    handler.setLevel(logging.INFO)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    logger = logging.getLogger("security")
    # Avoid duplicate handlers on repeated create_app() calls (tests)
    if not logger.handlers:
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def log_security_event(event_type: str, message: str, **kwargs: object) -> None:
    """Write a structured line to the security log.

    Example::

        log_security_event("LOGIN_FAILED", "Invalid credentials",
                           username="alice", ip="10.0.0.1")
        # → 2026-11-05 12:00:00 [WARNING] [LOGIN_FAILED] Invalid credentials username=alice ip=10.0.0.1
    """
    logger = logging.getLogger("security")
    extra = " ".join(f"{k}={v}" for k, v in kwargs.items())
    line = f"[{event_type}] {message}"
    if extra:
        line = f"{line} {extra}"

    if event_type in ("LOGIN_SUCCESS", "LOGOUT", "ROLE_CHANGED"):
        logger.info(line)
    else:
        logger.warning(line)
