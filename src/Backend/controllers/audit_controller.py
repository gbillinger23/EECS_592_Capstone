"""
audit_controller.py
===================
Business logic for the NetGuard audit log viewer endpoints.

Endpoints (wired in routes/audit_routes.py, all admin-only):
  GET /audit/logs                – Paginated, filtered audit log list
  GET /audit/logs/<user_id>      – All audit logs for a specific user
  GET /audit/export              – Stream full result set as CSV download
  GET /audit/archive/status      – Stub: describe the S3 archive job

All endpoints require @verify_token + @require_role("admin").
"""

import csv
import io
import logging

from flask import request, jsonify, Response

from services.dynamodb_service import query_audit_logs, get_all_audit_logs_for_export
from services.s3_archive_service import archive_old_logs

logger = logging.getLogger(__name__)

# Columns included in the CSV export (in order)
CSV_COLUMNS = [
    "timestamp", "logId", "userId", "userEmail", "role",
    "action", "resourceId", "ipAddress", "userAgent", "status",
]


# ===========================================================================
# GET /audit/logs
# ===========================================================================

def get_audit_logs():
    """
    Return a paginated, filtered list of audit log entries.

    Query parameters
    ----------------
    user_id    : str  – Filter to a specific userId
    action     : str  – Filter by action enum (LOGIN, LOGOUT, …)
    status     : str  – SUCCESS | FAILURE
    date_from  : str  – ISO-8601 lower bound  (e.g. 2025-01-01T00:00:00Z)
    date_to    : str  – ISO-8601 upper bound
    search     : str  – Substring match on userEmail or resourceId
    page_size  : int  – Max items per page (default 25, max 100)
    last_key   : str  – JSON-encoded DynamoDB pagination token

    Response 200
    ------------
    {
      "items": [...],
      "lastEvaluatedKey": {...} | null,
      "count": 25
    }
    """
    args = request.args

    # Parse and clamp page_size
    try:
        page_size = min(int(args.get("page_size", 25)), 100)
    except (TypeError, ValueError):
        page_size = 25

    # Parse optional DynamoDB pagination token
    last_key_raw = args.get("last_key")
    last_key     = None
    if last_key_raw:
        import json
        try:
            last_key = json.loads(last_key_raw)
        except Exception:
            return jsonify({"error": "Invalid last_key parameter"}), 400

    try:
        result = query_audit_logs(
            user_id            = args.get("user_id") or None,
            action             = args.get("action")  or None,
            status             = args.get("status")  or None,
            date_from          = args.get("date_from") or None,
            date_to            = args.get("date_to")   or None,
            search             = args.get("search")    or None,
            page_size          = page_size,
            last_evaluated_key = last_key,
        )
        return jsonify(result), 200
    except RuntimeError as exc:
        logger.error("[audit] get_audit_logs error: %s", exc)
        return jsonify({"error": "Failed to retrieve audit logs"}), 500


# ===========================================================================
# GET /audit/logs/<user_id>
# ===========================================================================

def get_user_audit_logs(user_id):
    """
    Return all audit log entries for a specific user (paginated).

    Path parameter
    --------------
    user_id : str – The userId to filter on

    Same query parameters as GET /audit/logs except user_id is taken
    from the path.

    Response 200
    ------------
    {"items": [...], "lastEvaluatedKey": {...}|null, "count": int}
    """
    args = request.args
    try:
        page_size = min(int(args.get("page_size", 25)), 100)
    except (TypeError, ValueError):
        page_size = 25

    last_key_raw = args.get("last_key")
    last_key     = None
    if last_key_raw:
        import json
        try:
            last_key = json.loads(last_key_raw)
        except Exception:
            return jsonify({"error": "Invalid last_key parameter"}), 400

    try:
        result = query_audit_logs(
            user_id            = user_id,
            action             = args.get("action")    or None,
            status             = args.get("status")    or None,
            date_from          = args.get("date_from") or None,
            date_to            = args.get("date_to")   or None,
            search             = args.get("search")    or None,
            page_size          = page_size,
            last_evaluated_key = last_key,
        )
        return jsonify(result), 200
    except RuntimeError as exc:
        logger.error("[audit] get_user_audit_logs error: %s", exc)
        return jsonify({"error": "Failed to retrieve audit logs"}), 500


# ===========================================================================
# GET /audit/export
# ===========================================================================

def export_audit_logs():
    """
    Export matching audit logs as a CSV file download (up to 5,000 rows).

    Accepts the same query parameters as GET /audit/logs.

    Response 200 – Content-Type: text/csv
    File name: netguard-audit-{YYYY-MM-DD}.csv

    Columns: timestamp, logId, userId, userEmail, role, action,
             resourceId, ipAddress, userAgent, status
    """
    args = request.args

    try:
        items = get_all_audit_logs_for_export(
            user_id   = args.get("user_id")   or None,
            action    = args.get("action")    or None,
            status    = args.get("status")    or None,
            date_from = args.get("date_from") or None,
            date_to   = args.get("date_to")   or None,
            search    = args.get("search")    or None,
            max_items = 5000,
        )
    except RuntimeError as exc:
        logger.error("[audit] export_audit_logs error: %s", exc)
        return jsonify({"error": "Failed to export audit logs"}), 500

    # ── Build CSV in-memory ───────────────────────────────────────────────────
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=CSV_COLUMNS,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    for item in items:
        # Flatten metadata dict to string for CSV
        if isinstance(item.get("metadata"), dict):
            item = {**item, "metadata": str(item["metadata"])}
        writer.writerow({col: item.get(col, "") for col in CSV_COLUMNS})

    from datetime import datetime, timezone
    date_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename  = f"netguard-audit-{date_str}.csv"
    csv_bytes = buf.getvalue().encode("utf-8")

    logger.info("[audit] CSV export: %d rows  file=%s", len(items), filename)

    return Response(
        csv_bytes,
        status=200,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(csv_bytes)),
        },
    )


# ===========================================================================
# GET /audit/archive/status
# ===========================================================================

def archive_status():
    """
    Return the stub status of the S3 archival process.

    Response 200
    ------------
    {
      "status": "stub — not yet deployed as a Lambda",
      "cutoffDate": "...",
      "targetBucket": "audit-logs-archive",
      ...
    }
    """
    status = archive_old_logs()
    return jsonify(status), 200
