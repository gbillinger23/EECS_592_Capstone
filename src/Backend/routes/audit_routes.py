"""
audit_routes.py
===============
Flask Blueprint wiring audit log viewer endpoints.

Prefix: /audit  (registered in app.py with url_prefix="/audit")

All routes require:
  1. @verify_token   – valid JWT in Authorization header
  2. @require_role("admin") – only admins can access audit logs

Role mismatches return 403 and are themselves logged as UNAUTHORIZED_ACCESS.

Routes
------
GET /audit/logs                – Paginated, filtered audit log list
GET /audit/logs/<user_id>      – Audit logs for a specific user
GET /audit/export              – CSV export of matching logs
GET /audit/archive/status      – S3 archival job stub status
"""

from flask import Blueprint

from middleware.verify_token import verify_token
from middleware.require_role import require_role
from middleware.audit_logger import audit_log
from controllers.audit_controller import (
    get_audit_logs,
    get_user_audit_logs,
    export_audit_logs,
    archive_status,
)

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("/logs", methods=["GET"])
@verify_token
@require_role("admin")
@audit_log(action="DASHBOARD_VIEW")
def audit_logs_route():
    """
    GET /audit/logs

    Returns a paginated list of audit log entries.
    Supports query params: user_id, action, status, date_from, date_to,
    search, page_size, last_key.
    """
    return get_audit_logs()


@audit_bp.route("/logs/<user_id>", methods=["GET"])
@verify_token
@require_role("admin")
@audit_log(action="DASHBOARD_VIEW")
def user_audit_logs_route(user_id):
    """
    GET /audit/logs/<user_id>

    Returns all audit logs for the given userId (paginated).
    """
    return get_user_audit_logs(user_id)


@audit_bp.route("/export", methods=["GET"])
@verify_token
@require_role("admin")
@audit_log(action="EXPORT")
def export_route():
    """
    GET /audit/export

    Streams a CSV file containing up to 5,000 matching audit log rows.
    Accepts the same filter query params as GET /audit/logs.
    """
    return export_audit_logs()


@audit_bp.route("/archive/status", methods=["GET"])
@verify_token
@require_role("admin")
def archive_status_route():
    """
    GET /audit/archive/status

    Returns the stub description of the scheduled S3 archival job.
    """
    return archive_status()
