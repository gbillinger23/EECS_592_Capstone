"""
auth_controller.py
==================
Business logic for NetGuard authentication endpoints.

Endpoints implemented here (wired in routes/auth_routes.py):
  POST /auth/login   – Validate credentials, return signed JWT
  POST /auth/logout  – Blacklist the caller's token
  GET  /auth/me      – Return current user info from JWT payload

Password security
-----------------
- Passwords are stored as bcrypt hashes (rounds=12) in DynamoDB.
- Failed login attempts are logged with status=FAILURE in AuditLogs.
- A generic error message is returned on failure to prevent user enumeration.

Audit logging
-------------
All three endpoints emit an audit event asynchronously via a daemon thread.
"""

import logging
import threading

from flask import request, jsonify, g

from auth.jwt_handler import create_token
from auth.password_handler import check_password
from services.dynamodb_service import find_user_by_email, log_audit_event
from middleware.verify_token import add_to_blacklist
from models.audit_log_model import ACTIONS, STATUS

logger = logging.getLogger(__name__)


# ===========================================================================
# POST /auth/login
# ===========================================================================

def login():
    """
    Authenticate a user with email + password and return a signed JWT.

    Request body (JSON)
    -------------------
    {
      "email":    "user@netguard.io",
      "password": "plain_text_password"
    }

    Response 200
    ------------
    {
      "token": "<JWT string>",
      "user":  {"userId": "...", "email": "...", "role": "..."}
    }

    Response 400 – Missing fields
    Response 401 – Invalid credentials
    Response 500 – Unexpected server error
    """
    data = request.get_json(silent=True) or {}

    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    ip_address = request.remote_addr or "unknown"
    user_agent = request.headers.get("User-Agent", "")

    # ── Look up user ──────────────────────────────────────────────────────────
    try:
        user = find_user_by_email(email)
    except Exception as exc:
        logger.error("[login] DynamoDB lookup failed: %s", exc)
        return jsonify({"error": "Authentication service unavailable"}), 503

    # ── Verify password ───────────────────────────────────────────────────────
    if not user or not check_password(password, user.get("passwordHash", "")):
        # Use generic message to prevent user enumeration
        logger.info("[login] Failed login attempt for email='%s'", email)

        _async_audit(
            user_id    = user["userId"] if user else "unknown",
            user_email = email,
            role       = user["role"]   if user else "unknown",
            action     = ACTIONS["LOGIN"],
            ip_address = ip_address,
            user_agent = user_agent,
            status     = STATUS["FAILURE"],
            metadata   = {"reason": "invalid_credentials"},
        )

        return jsonify({"error": "Invalid email or password."}), 401

    # ── Create JWT ────────────────────────────────────────────────────────────
    token = create_token(
        user_id=user["userId"],
        email=user["email"],
        role=user["role"],
    )

    logger.info("[login] Successful login: %s (%s)", user["email"], user["role"])

    _async_audit(
        user_id    = user["userId"],
        user_email = user["email"],
        role       = user["role"],
        action     = ACTIONS["LOGIN"],
        ip_address = ip_address,
        user_agent = user_agent,
        status     = STATUS["SUCCESS"],
    )

    return jsonify({
        "token": token,
        "user":  {
            "userId": user["userId"],
            "email":  user["email"],
            "role":   user["role"],
        },
    }), 200


# ===========================================================================
# POST /auth/logout
# ===========================================================================

def logout():
    """
    Invalidate the caller's JWT by adding it to the in-memory blacklist.

    The route must be protected by @verify_token so g.user and g.token
    are already populated when this controller runs.

    Response 200
    ------------
    {"message": "Logged out successfully"}
    """
    token      = getattr(g, "token", None)
    user       = getattr(g, "user",  {}) or {}
    ip_address = request.remote_addr or "unknown"
    user_agent = request.headers.get("User-Agent", "")

    if token:
        add_to_blacklist(token)
        logger.info("[logout] Invalidated token for user='%s'", user.get("email"))

    _async_audit(
        user_id    = user.get("sub",   "unknown"),
        user_email = user.get("email", "unknown"),
        role       = user.get("role",  "unknown"),
        action     = ACTIONS["LOGOUT"],
        ip_address = ip_address,
        user_agent = user_agent,
        status     = STATUS["SUCCESS"],
    )

    return jsonify({"message": "Logged out successfully"}), 200


# ===========================================================================
# GET /auth/me
# ===========================================================================

def me():
    """
    Return the current user's info extracted from the validated JWT.

    The route must be protected by @verify_token.

    Response 200
    ------------
    {
      "userId": "...",
      "email":  "...",
      "role":   "..."
    }
    """
    user = getattr(g, "user", {}) or {}

    return jsonify({
        "userId": user.get("sub"),
        "email":  user.get("email"),
        "role":   user.get("role"),
    }), 200


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _async_audit(**kwargs) -> None:
    """
    Fire-and-forget audit log write.  Runs in a daemon thread so it never
    blocks the HTTP response, even if DynamoDB is slow or unreachable.

    Parameters
    ----------
    **kwargs – Keyword arguments forwarded to log_audit_event()
    """
    def _write():
        try:
            log_audit_event(**kwargs)
        except Exception as exc:
            logger.error("[auth] Audit log write failed: %s", exc)

    t = threading.Thread(target=_write, daemon=True)
    t.start()
