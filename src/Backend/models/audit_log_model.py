"""
audit_log_model.py
==================
Schema constants and factory for AuditLog entries written to DynamoDB.

DynamoDB Table: AuditLogs
  Partition key : userId    (String)
  Sort key      : timestamp (ISO-8601 String)
  GSI           : action-index  on  action  (for filtering by event type)
  TTL field     : expiresAt (Unix epoch seconds, 90 days from timestamp)
"""

# ---------------------------------------------------------------------------
# Action enum
# ---------------------------------------------------------------------------
ACTIONS = {
    "LOGIN":               "LOGIN",
    "LOGOUT":              "LOGOUT",
    "SEARCH":              "SEARCH",
    "RULE_EDIT":           "RULE_EDIT",
    "ALERT_ACK":           "ALERT_ACK",
    "DASHBOARD_VIEW":      "DASHBOARD_VIEW",
    "EXPORT":              "EXPORT",
    "SETTINGS_CHANGE":     "SETTINGS_CHANGE",
    "UNAUTHORIZED_ACCESS": "UNAUTHORIZED_ACCESS",
}

VALID_ACTIONS = set(ACTIONS.values())

# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------
STATUS = {
    "SUCCESS": "SUCCESS",
    "FAILURE": "FAILURE",
}

VALID_STATUS = set(STATUS.values())


def create_audit_log_entry(
    *,
    log_id,
    user_id,
    user_email,
    role,
    action,
    ip_address,
    user_agent,
    status,
    timestamp,
    expires_at,
    resource_id=None,
    metadata=None,
):
    """
    Build and validate an audit log entry dict.

    Parameters
    ----------
    log_id      : str  – UUID v4
    user_id     : str  – The authenticated user's ID
    user_email  : str  – The authenticated user's email
    role        : str  – admin | analyst | viewer
    action      : str  – Must be a value in VALID_ACTIONS
    ip_address  : str  – Client IP
    user_agent  : str  – Client User-Agent header value
    status      : str  – SUCCESS | FAILURE
    timestamp   : str  – ISO-8601 UTC timestamp
    expires_at  : int  – Unix epoch seconds (90 days from timestamp)
    resource_id : str  – Optional; e.g. ruleId, alertId
    metadata    : dict – Optional extra context (old/new values for edits, etc.)

    Returns
    -------
    dict – Validated entry ready for DynamoDB PutItem.

    Raises
    ------
    ValueError – If action or status is not in the allowed enums.
    """
    if action not in VALID_ACTIONS:
        raise ValueError(f"Invalid action '{action}'. Must be one of: {VALID_ACTIONS}")
    if status not in VALID_STATUS:
        raise ValueError(f"Invalid status '{status}'. Must be SUCCESS or FAILURE.")

    entry = {
        "logId":      log_id,
        "userId":     user_id,
        "userEmail":  user_email,
        "role":       role,
        "action":     action,
        "ipAddress":  ip_address,
        "userAgent":  user_agent,
        "status":     status,
        "timestamp":  timestamp,
        "expiresAt":  expires_at,
        "metadata":   metadata or {},
    }
    if resource_id is not None:
        entry["resourceId"] = resource_id

    return entry
