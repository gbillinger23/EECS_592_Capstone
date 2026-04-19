"""
audit_logger.py
===============
Automatic audit-logging decorator for NetGuard Flask routes.

How it works
------------
Wrap any protected route with ``@audit_log(action="LOGIN")`` (explicit) or
leave ``action=None`` to have the action inferred from the HTTP method + path
pattern.  After the route handler returns, a daemon thread writes the event
to DynamoDB so the HTTP response is never delayed.

Route → action inference map (used when action=None)
-----------------------------------------------------
POST  /auth/login                → LOGIN
POST  /auth/logout               → LOGOUT
GET   /api/logs/search/*         → SEARCH
PUT   /api/rules/:id             → RULE_EDIT
PATCH /api/rules/:id             → RULE_EDIT
POST  /api/alerts/:id/acknowledge→ ALERT_ACK
GET   /api/dashboard*            → DASHBOARD_VIEW
GET   /api/export* or /audit/export → EXPORT

Usage
-----
    from middleware.verify_token import verify_token
    from middleware.audit_logger import audit_log

    @app.route("/auth/login", methods=["POST"])
    @audit_log(action="LOGIN")               # explicit
    def login():
        ...

    @app.route("/api/logs/search/local")
    @verify_token
    @audit_log()                             # inferred from path
    def search_logs():
        ...

Notes
-----
- Failures (HTTP ≥ 400) are logged with status=FAILURE.
- The decorator reads g.user (set by verify_token) for user identity.
  If g.user is not present the audit entry uses "anonymous" placeholders.
- Audit writes are fire-and-forget: .start() on a daemon thread; errors
  are caught and logged — they never propagate to the caller.
"""

import re
import logging
import threading
from functools import wraps

from flask import g, request

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Route → action inference table
# ---------------------------------------------------------------------------
_ROUTE_ACTION_MAP = [
    # (method_pattern, path_regex, action)
    ("POST",  re.compile(r"^/auth/login$"),              "LOGIN"),
    ("POST",  re.compile(r"^/auth/logout$"),             "LOGOUT"),
    ("GET",   re.compile(r"^/api/logs/search"),          "SEARCH"),
    ("PUT",   re.compile(r"^/api/rules/"),               "RULE_EDIT"),
    ("PATCH", re.compile(r"^/api/rules/"),               "RULE_EDIT"),
    ("POST",  re.compile(r"^/api/alerts/.*acknowledge"), "ALERT_ACK"),
    ("GET",   re.compile(r"^/api/dashboard"),            "DASHBOARD_VIEW"),
    ("GET",   re.compile(r"^/api/export"),               "EXPORT"),
    ("GET",   re.compile(r"^/audit/export"),             "EXPORT"),
]


def _infer_action(method: str, path: str) -> str | None:
    """
    Infer an ACTIONS enum value from the HTTP method and request path.

    Parameters
    ----------
    method : str – HTTP method (GET, POST, PUT, PATCH, …)
    path   : str – Request path (e.g. /api/rules/port_scan)

    Returns
    -------
    str|None – Action string or None if no mapping found
    """
    for m, pattern, action in _ROUTE_ACTION_MAP:
        if method.upper() == m and pattern.search(path):
            return action
    return None


# ---------------------------------------------------------------------------
# audit_log decorator
# ---------------------------------------------------------------------------

def audit_log(action: str | None = None):
    """
    Decorator factory that writes an audit entry to DynamoDB after the route
    handler returns.

    Parameters
    ----------
    action : str|None
        Explicit action name (one of ACTIONS enum values).
        If None, the action is inferred from the request method + path.
        If neither resolves to a known action, no log entry is written.

    Returns
    -------
    callable – The actual Flask route decorator.

    Notes
    -----
    The audit write is asynchronous (daemon thread).  A failure in the write
    never affects the HTTP response.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # ── Execute the actual route handler ─────────────────────────────
            response = f(*args, **kwargs)

            # ── Determine status from response ───────────────────────────────
            # Flask route functions may return (body, status_code) tuples or
            # plain Response objects.
            try:
                if isinstance(response, tuple):
                    status_code = response[1] if len(response) > 1 else 200
                else:
                    status_code = getattr(response, "status_code", 200)
            except Exception:
                status_code = 200

            audit_status = "FAILURE" if int(status_code) >= 400 else "SUCCESS"

            # ── Resolve action ────────────────────────────────────────────────
            resolved_action = action or _infer_action(request.method, request.path)
            if not resolved_action:
                return response  # No audit needed for unmapped routes

            # ── Collect identity from g.user (set by verify_token) ────────────
            user       = getattr(g, "user", None) or {}
            user_id    = user.get("sub",   "anonymous")
            user_email = user.get("email", "anonymous")
            user_role  = user.get("role",  "unknown")

            # ── Extract optional resourceId from route params ──────────────────
            resource_id = (
                kwargs.get("rule_id")
                or kwargs.get("alert_id")
                or kwargs.get("user_id")
                or None
            )

            # ── Fire-and-forget DynamoDB write ────────────────────────────────
            _fire_audit_write(
                user_id    =user_id,
                user_email =user_email,
                role       =user_role,
                action     =resolved_action,
                ip_address =request.remote_addr or "unknown",
                user_agent =request.headers.get("User-Agent", ""),
                status     =audit_status,
                resource_id=resource_id,
                metadata   ={"method": request.method, "path": request.path},
            )

            return response

        return decorated
    return decorator


# ---------------------------------------------------------------------------
# Internal helper — runs in background thread
# ---------------------------------------------------------------------------

def _fire_audit_write(**event_kwargs) -> None:
    """
    Start a daemon thread that writes one audit entry to DynamoDB.

    All keyword arguments are forwarded directly to
    ``services.dynamodb_service.log_audit_event``.
    """
    def _write():
        try:
            from services.dynamodb_service import log_audit_event
            log_audit_event(**event_kwargs)
        except Exception as exc:
            logger.error("[audit_logger] DynamoDB write failed: %s", exc)

    t = threading.Thread(target=_write, daemon=True)
    t.start()
