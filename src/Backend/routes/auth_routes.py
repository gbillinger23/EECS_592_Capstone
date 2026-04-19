"""
auth_routes.py
==============
Flask Blueprint wiring authentication endpoints.

Prefix: /auth  (registered in app.py as blueprint with url_prefix="/auth")

Routes
------
POST /auth/login   – Public; no middleware needed
POST /auth/logout  – Protected by @verify_token
GET  /auth/me      – Protected by @verify_token
"""

from flask import Blueprint

from middleware.verify_token import verify_token
from middleware.audit_logger import audit_log
from controllers.auth_controller import login, logout, me

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["POST"])
@audit_log(action="LOGIN")
def login_route():
    """
    POST /auth/login

    Authenticate with email + password; returns a signed JWT.
    The @audit_log decorator logs the result (SUCCESS or FAILURE) to DynamoDB
    asynchronously — the HTTP response is never delayed.
    """
    return login()


@auth_bp.route("/logout", methods=["POST"])
@verify_token
@audit_log(action="LOGOUT")
def logout_route():
    """
    POST /auth/logout

    Invalidate the caller's current JWT.
    Requires a valid Bearer token in the Authorization header.
    """
    return logout()


@auth_bp.route("/me", methods=["GET"])
@verify_token
def me_route():
    """
    GET /auth/me

    Return the current user's identity decoded from the JWT.
    Requires a valid Bearer token in the Authorization header.
    No audit log needed (read-only identity check).
    """
    return me()
