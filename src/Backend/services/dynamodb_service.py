"""
dynamodb_service.py
===================
All DynamoDB interactions for NetGuard auth and audit logging.

Tables
------
AuditLogs      – PK: userId (S)  SK: timestamp (S)  GSI: action-index on action
NetGuardUsers  – PK: email   (S)

Required environment variables
-------------------------------
AWS_REGION          – e.g. us-east-2  (default: us-east-2)
DYNAMO_AUDIT_TABLE  – AuditLogs table name  (default: AuditLogs)
DYNAMO_USERS_TABLE  – Users table name      (default: NetGuardUsers)

Notes
-----
- All DynamoDB calls are wrapped in try/except with structured error logging.
- TTL field expiresAt is set to 90 days from the event timestamp.
- Table creation / user seeding are idempotent — safe to call on every startup.
"""

import os
import uuid
import json
import logging
from datetime import datetime, timezone, timedelta

import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
AWS_REGION         = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "us-east-2")
AUDIT_TABLE_NAME   = os.environ.get("DYNAMO_AUDIT_TABLE", "AuditLogs")
USERS_TABLE_NAME   = os.environ.get("DYNAMO_USERS_TABLE", "NetGuardUsers")
TTL_DAYS           = 90

# ---------------------------------------------------------------------------
# DynamoDB resource (lazy — doesn't connect until first call)
# ---------------------------------------------------------------------------
_dynamodb = None


def _get_dynamodb():
    """Return a (cached) boto3 DynamoDB resource."""
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    return _dynamodb


def _audit_table():
    return _get_dynamodb().Table(AUDIT_TABLE_NAME)


def _users_table():
    return _get_dynamodb().Table(USERS_TABLE_NAME)


# ===========================================================================
# Table setup (call once at application startup)
# ===========================================================================

def setup_tables():
    """
    Create AuditLogs and NetGuardUsers tables if they don't already exist.

    Uses ``ACTIVE`` waiter so the function blocks until tables are ready.
    Safe to call on every startup — existing tables are left untouched.

    Returns
    -------
    dict – {"audit": "created"|"exists", "users": "created"|"exists"}
    """
    client = boto3.client("dynamodb", region_name=AWS_REGION)
    results = {}

    # ── AuditLogs ────────────────────────────────────────────────────────────
    try:
        client.describe_table(TableName=AUDIT_TABLE_NAME)
        logger.info("[dynamo] Table '%s' already exists", AUDIT_TABLE_NAME)
        results["audit"] = "exists"
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        logger.info("[dynamo] Creating table '%s'…", AUDIT_TABLE_NAME)
        client.create_table(
            TableName=AUDIT_TABLE_NAME,
            KeySchema=[
                {"AttributeName": "userId",    "KeyType": "HASH"},
                {"AttributeName": "timestamp", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "userId",    "AttributeType": "S"},
                {"AttributeName": "timestamp", "AttributeType": "S"},
                {"AttributeName": "action",    "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "action-index",
                    "KeySchema": [
                        {"AttributeName": "action",    "KeyType": "HASH"},
                        {"AttributeName": "timestamp", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "BillingMode": "PAY_PER_REQUEST",
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        # Enable TTL on expiresAt
        waiter = client.get_waiter("table_exists")
        waiter.wait(TableName=AUDIT_TABLE_NAME)
        client.update_time_to_live(
            TableName=AUDIT_TABLE_NAME,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "expiresAt"},
        )
        logger.info("[dynamo] Table '%s' created with TTL on expiresAt", AUDIT_TABLE_NAME)
        results["audit"] = "created"

    # ── NetGuardUsers ─────────────────────────────────────────────────────────
    try:
        client.describe_table(TableName=USERS_TABLE_NAME)
        logger.info("[dynamo] Table '%s' already exists", USERS_TABLE_NAME)
        results["users"] = "exists"
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        logger.info("[dynamo] Creating table '%s'…", USERS_TABLE_NAME)
        client.create_table(
            TableName=USERS_TABLE_NAME,
            KeySchema=[
                {"AttributeName": "email", "KeyType": "HASH"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "email", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        waiter = client.get_waiter("table_exists")
        waiter.wait(TableName=USERS_TABLE_NAME)
        logger.info("[dynamo] Table '%s' created", USERS_TABLE_NAME)
        results["users"] = "created"

    return results


# ===========================================================================
# User operations
# ===========================================================================

def find_user_by_email(email: str) -> dict | None:
    """
    Look up a user by email address.

    Parameters
    ----------
    email : str – The user's email (case-insensitive lookup)

    Returns
    -------
    dict | None – User record or None if not found.

    Raises
    ------
    RuntimeError – On DynamoDB client errors.
    """
    try:
        response = _users_table().get_item(Key={"email": email.lower()})
        item = response.get("Item")
        logger.debug("[dynamo] find_user_by_email('%s') → %s", email, "found" if item else "not found")
        return item
    except (ClientError, BotoCoreError) as exc:
        logger.error("[dynamo] find_user_by_email error: %s", exc)
        raise RuntimeError("Database lookup failed") from exc


def create_user_record(*, user_id: str, email: str, password_hash: str, role: str, created_at: str) -> dict:
    """
    Persist a new user record to NetGuardUsers.

    Parameters
    ----------
    user_id       : str – UUID v4
    email         : str – Stored lower-cased
    password_hash : str – bcrypt hash
    role          : str – admin | analyst | viewer
    created_at    : str – ISO-8601 UTC timestamp

    Returns
    -------
    dict – The stored user record (without passwordHash for safety).

    Raises
    ------
    RuntimeError – On DynamoDB client errors.
    """
    item = {
        "userId":       user_id,
        "email":        email.lower(),
        "passwordHash": password_hash,
        "role":         role,
        "createdAt":    created_at,
    }
    try:
        _users_table().put_item(Item=item)
        logger.info("[dynamo] Created user '%s' with role '%s'", email, role)
        return {k: v for k, v in item.items() if k != "passwordHash"}
    except (ClientError, BotoCoreError) as exc:
        logger.error("[dynamo] create_user_record error: %s", exc)
        raise RuntimeError("Failed to create user") from exc


def seed_demo_users():
    """
    Seed the NetGuardUsers table with demo accounts if it is empty.

    Demo accounts (bcrypt-hashed passwords generated at runtime):
      admin@netguard.io   / netguard2026  role=admin
      analyst@netguard.io / analyst2026   role=analyst
      client@netguard.io  / client2026    role=viewer

    This function is idempotent — if users already exist, nothing changes.
    """
    from auth.password_handler import hash_password  # local import to avoid circular deps

    demo_users = [
        {"email": "admin@netguard.io",   "password": "netguard2026", "role": "admin"},
        {"email": "analyst@netguard.io", "password": "analyst2026",  "role": "analyst"},
        {"email": "client@netguard.io",  "password": "client2026",   "role": "viewer"},
    ]

    now = datetime.now(timezone.utc).isoformat()
    seeded = 0

    for demo in demo_users:
        existing = None
        try:
            existing = find_user_by_email(demo["email"])
        except Exception:
            pass  # If table doesn't exist yet, skip gracefully

        if not existing:
            try:
                create_user_record(
                    user_id=str(uuid.uuid4()),
                    email=demo["email"],
                    password_hash=hash_password(demo["password"]),
                    role=demo["role"],
                    created_at=now,
                )
                seeded += 1
                logger.info("[dynamo] Seeded demo user: %s (%s)", demo["email"], demo["role"])
            except Exception as exc:
                logger.warning("[dynamo] Could not seed user '%s': %s", demo["email"], exc)

    if seeded:
        logger.info("[dynamo] Seeded %d demo user(s)", seeded)
    else:
        logger.info("[dynamo] Demo users already exist — skipping seed")


# ===========================================================================
# Audit log operations
# ===========================================================================

def log_audit_event(
    *,
    user_id: str,
    user_email: str,
    role: str,
    action: str,
    ip_address: str,
    user_agent: str,
    status: str,
    resource_id: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """
    Write a single audit event to DynamoDB (AuditLogs table).

    This function is designed to be called **asynchronously** (fire-and-forget)
    via a daemon thread so it never blocks an HTTP response.

    Parameters
    ----------
    user_id     : str       – Authenticated user ID
    user_email  : str       – Authenticated user email
    role        : str       – User's RBAC role
    action      : str       – One of ACTIONS enum values
    ip_address  : str       – Client IP address
    user_agent  : str       – Client User-Agent string
    status      : str       – SUCCESS | FAILURE
    resource_id : str|None  – Optional resource identifier (ruleId, alertId…)
    metadata    : dict|None – Optional extra context dict

    Returns
    -------
    dict – The item that was written to DynamoDB.

    Raises
    ------
    RuntimeError – On DynamoDB client errors (logged, not surfaced to caller).
    """
    now        = datetime.now(timezone.utc)
    timestamp  = now.isoformat()
    expires_at = int((now + timedelta(days=TTL_DAYS)).timestamp())
    log_id     = str(uuid.uuid4())

    item = {
        "userId":     user_id,
        "timestamp":  timestamp,
        "logId":      log_id,
        "userEmail":  user_email,
        "role":       role,
        "action":     action,
        "ipAddress":  ip_address,
        "userAgent":  user_agent or "",
        "status":     status,
        "metadata":   metadata or {},
        "expiresAt":  expires_at,
    }
    if resource_id:
        item["resourceId"] = resource_id

    try:
        _audit_table().put_item(Item=item)
        logger.debug(
            "[audit] %s  user=%s  action=%s  status=%s",
            log_id, user_email, action, status,
        )
        return item
    except (ClientError, BotoCoreError) as exc:
        logger.error("[audit] DynamoDB write failed: %s", exc)
        raise RuntimeError("Audit log write failed") from exc


def query_audit_logs(
    *,
    user_id: str | None = None,
    action: str | None = None,
    status: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    search: str | None = None,
    page_size: int = 25,
    last_evaluated_key: dict | None = None,
) -> dict:
    """
    Query the AuditLogs table with optional filters and pagination.

    Uses DynamoDB Scan with FilterExpression because the admin viewer needs
    cross-user results.  For high-volume production use, add a composite GSI
    (e.g. ALL_USERS# partition + timestamp sort key).

    Parameters
    ----------
    user_id             : str|None  – Filter to a specific user ID
    action              : str|None  – Filter by action enum value
    status              : str|None  – SUCCESS | FAILURE
    date_from           : str|None  – ISO-8601 lower bound (inclusive)
    date_to             : str|None  – ISO-8601 upper bound (inclusive)
    search              : str|None  – Substring match on userEmail or resourceId
    page_size           : int       – Max items per page (default 25)
    last_evaluated_key  : dict|None – DynamoDB pagination token from prior call

    Returns
    -------
    dict – {
        "items": [...],
        "lastEvaluatedKey": dict|None,  # None means no more pages
        "count": int
    }
    """
    filter_parts = []
    expr_values  = {}
    expr_names   = {}

    if user_id:
        filter_parts.append("userId = :uid")
        expr_values[":uid"] = user_id

    if action:
        filter_parts.append("#act = :action")
        expr_names["#act"] = "action"
        expr_values[":action"] = action

    if status:
        filter_parts.append("#st = :status")
        expr_names["#st"] = "status"
        expr_values[":status"] = status

    if date_from:
        filter_parts.append("#ts >= :date_from")
        expr_names["#ts"] = "timestamp"
        expr_values[":date_from"] = date_from

    if date_to:
        filter_parts.append("#ts <= :date_to")
        expr_names.setdefault("#ts", "timestamp")
        expr_values[":date_to"] = date_to

    if search:
        filter_parts.append(
            "(contains(userEmail, :search) OR contains(resourceId, :search))"
        )
        expr_values[":search"] = search

    scan_kwargs = {"Limit": page_size}

    if filter_parts:
        scan_kwargs["FilterExpression"] = " AND ".join(filter_parts)
        scan_kwargs["ExpressionAttributeValues"] = expr_values
        if expr_names:
            scan_kwargs["ExpressionAttributeNames"] = expr_names

    if last_evaluated_key:
        scan_kwargs["ExclusiveStartKey"] = last_evaluated_key

    try:
        response = _audit_table().scan(**scan_kwargs)
        return {
            "items":            response.get("Items", []),
            "lastEvaluatedKey": response.get("LastEvaluatedKey"),
            "count":            response.get("Count", 0),
        }
    except (ClientError, BotoCoreError) as exc:
        logger.error("[dynamo] query_audit_logs error: %s", exc)
        raise RuntimeError("Audit log query failed") from exc


def get_all_audit_logs_for_export(
    *,
    user_id: str | None = None,
    action: str | None = None,
    status: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    search: str | None = None,
    max_items: int = 5000,
) -> list:
    """
    Scan all pages matching the given filters up to max_items.
    Used exclusively by the CSV export endpoint.

    Returns
    -------
    list – Flat list of audit log dicts.
    """
    all_items = []
    last_key  = None

    while True:
        result = query_audit_logs(
            user_id=user_id,
            action=action,
            status=status,
            date_from=date_from,
            date_to=date_to,
            search=search,
            page_size=min(100, max_items - len(all_items)),
            last_evaluated_key=last_key,
        )
        all_items.extend(result["items"])
        last_key = result.get("lastEvaluatedKey")

        if not last_key or len(all_items) >= max_items:
            break

    return all_items[:max_items]
