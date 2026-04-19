"""
require_role.py
===============
Role-based access control (RBAC) decorator for NetGuard Flask routes.

MUST be applied AFTER @verify_token so that g.user is already populated.

Usage
-----
    from middleware.verify_token import verify_token
    from middleware.require_role import require_role

    @app.route("/admin/audit")
    @verify_token
    @require_role("admin")
    def audit_page():
        ...

    # Multiple roles allowed:
    @app.route("/api/rules", methods=["PUT"])
    @verify_token
    @require_role("admin", "analyst")
    def update_rule():
        ...

On role mismatch
----------------
- Returns HTTP 403 with JSON body: {"error": "Insufficient permissions"}
- Fires an asynchronous UNAUTHORIZED_ACCESS audit log entry in DynamoDB
  (fire-and-forget via daemon thread — does NOT slow the 403 response)
"""

import logging
import threading
from functools import wraps

from flask import g, request, jsonify

logger = logging.getLogger(__name__)


def require_role(*allowed_roles: str):
    """
    Decorator factory that restricts a route to users whose role is in
    ``allowed_roles``.

    Parameters
    ----------
    *allowed_roles : str – One or more role strings (e.g. "admin", "analyst")

    Returns
    -------
    callable – The actual decorator applied to the route function.

    HTTP responses
    --------------
    403 – User's role is not in ``allowed_roles``
          Body: {"error": "Insufficient permissions"}
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = getattr(g, "user", None)
            user_role = (user or {}).get("role", "")

            if user_role not in allowed_roles:
                logger.warning(
                    "[require_role] 403 — user=%s  role=%s  required=%s  path=%s",
                    (user or {}).get("email", "unknown"),
                    user_role,
                    allowed_roles,
                    request.path,
                )

                # ── Fire-and-forget audit log for UNAUTHORIZED_ACCESS ─────────
                _fire_unauthorized_audit_log(user, allowed_roles)

                return jsonify({"error": "Insufficient permissions"}), 403

            return f(*args, **kwargs)

        return decorated
    return decorator


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fire_unauthorized_audit_log(user: dict | None, required_roles: tuple) -> None:
    """
    Write an UNAUTHORIZED_ACCESS audit entry to DynamoDB without blocking
    the HTTP response.

    Parameters
    ----------
    user          : dict|None – The g.user payload (may be None if no token)
    required_roles: tuple     – The roles that were required for the route
    """
    def _write():
        try:
            from services.dynamodb_service import log_audit_event
            from models.audit_log_model import ACTIONS, STATUS

            log_audit_event(
                user_id    = (user or {}).get("sub",   "unknown"),
                user_email = (user or {}).get("email", "unknown"),
                role       = (user or {}).get("role",  "unknown"),
                action     = ACTIONS["UNAUTHORIZED_ACCESS"],
                ip_address = request.remote_addr or "unknown",
                user_agent = request.headers.get("User-Agent", ""),
                status     = STATUS["FAILURE"],
                resource_id= request.path,
                metadata   = {
                    "requiredRoles": list(required_roles),
                    "userRole":      (user or {}).get("role", "unknown"),
                    "method":        request.method,
                },
            )
        except Exception as exc:
            logger.error("[require_role] Audit log write failed: %s", exc)

    t = threading.Thread(target=_write, daemon=True)
    t.start()
