"""
user_model.py
=============
Schema constants and factory for NetGuard user records stored in DynamoDB.

DynamoDB Table: NetGuardUsers
  Partition key : email (String)  — looked up by email on every login
  Attributes    : userId, email, passwordHash, role, createdAt
"""

# ---------------------------------------------------------------------------
# Role enum
# ---------------------------------------------------------------------------
ROLES = {
    "ADMIN":   "admin",
    "ANALYST": "analyst",
    "VIEWER":  "viewer",
}

VALID_ROLES = set(ROLES.values())


def create_user(*, user_id, email, password_hash, role, created_at):
    """
    Build and validate a user record dict.

    Parameters
    ----------
    user_id       : str  – UUID v4
    email         : str  – User's email address (also the DynamoDB PK)
    password_hash : str  – bcrypt hash of the user's password
    role          : str  – admin | analyst | viewer
    created_at    : str  – ISO-8601 UTC timestamp

    Returns
    -------
    dict – Validated user record ready for DynamoDB PutItem.

    Raises
    ------
    ValueError – If role is not in VALID_ROLES.
    """
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Must be one of: {VALID_ROLES}")

    return {
        "userId":       user_id,
        "email":        email,
        "passwordHash": password_hash,
        "role":         role,
        "createdAt":    created_at,
    }
