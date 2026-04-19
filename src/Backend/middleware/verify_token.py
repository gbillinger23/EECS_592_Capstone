"""
verify_token.py
===============
JWT verification middleware for NetGuard Flask routes.

Usage (decorator pattern)
--------------------------
    from middleware.verify_token import verify_token

    @app.route("/api/protected")
    @verify_token
    def protected_route():
        user = g.user   # dict: {sub, email, role, iat, exp}
        ...

Token blacklist
---------------
``_token_blacklist`` is an in-memory set protected by a threading.Lock.
On logout, the token is added here and rejected on subsequent requests.

Limitation: The blacklist is cleared on server restart. For multi-instance
deployments, store invalidated tokens in DynamoDB or Redis instead.
"""

import logging
import threading
from functools import wraps

import jwt
from flask import request, jsonify, g

from auth.jwt_handler import verify_token_payload

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory token blacklist (logout invalidation)
# ---------------------------------------------------------------------------
_token_blacklist: set[str] = set()
_blacklist_lock             = threading.Lock()


def add_to_blacklist(token: str) -> None:
    """
    Add a JWT to the blacklist so subsequent requests with this token are
    rejected as invalid, effectively implementing logout.

    Parameters
    ----------
    token : str – The raw JWT string to invalidate
    """
    with _blacklist_lock:
        _token_blacklist.add(token)
    logger.debug("[verify_token] Token added to blacklist (len=%d)", len(_token_blacklist))


def is_blacklisted(token: str) -> bool:
    """
    Check whether a token has been invalidated.

    Parameters
    ----------
    token : str – Raw JWT string

    Returns
    -------
    bool – True if the token is on the blacklist
    """
    with _blacklist_lock:
        return token in _token_blacklist


# ---------------------------------------------------------------------------
# verify_token decorator
# ---------------------------------------------------------------------------

def verify_token(f):
    """
    Flask route decorator that validates the Authorization: Bearer <JWT> header.

    On success:
      - Sets ``flask.g.user``  = decoded JWT payload (sub, email, role, iat, exp)
      - Sets ``flask.g.token`` = raw JWT string  (needed for logout blacklisting)

    On failure:
      - Returns 401 JSON response; the route function is NOT called.

    Parameters
    ----------
    f : callable – The Flask route function to protect

    Returns
    -------
    callable – Wrapped route function

    HTTP responses
    --------------
    401 – No token provided / token blacklisted / expired / invalid signature
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            logger.warning(
                "[verify_token] 401 — missing/malformed Authorization header  path=%s",
                request.path,
            )
            return jsonify({"error": "Access denied. No token provided."}), 401

        token = auth_header[len("Bearer "):]

        if is_blacklisted(token):
            logger.warning("[verify_token] 401 — blacklisted token  path=%s", request.path)
            return jsonify({"error": "Token has been invalidated. Please log in again."}), 401

        try:
            payload    = verify_token_payload(token)
            g.user     = payload
            g.token    = token
            logger.debug(
                "[verify_token] ✓ user=%s  role=%s  path=%s",
                payload.get("email"), payload.get("role"), request.path,
            )
        except jwt.ExpiredSignatureError:
            logger.info("[verify_token] 401 — expired token  path=%s", request.path)
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError as exc:
            logger.warning("[verify_token] 401 — invalid token: %s  path=%s", exc, request.path)
            return jsonify({"error": "Invalid token."}), 401

        return f(*args, **kwargs)

    return decorated
