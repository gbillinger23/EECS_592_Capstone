"""
jwt_handler.py
==============
JWT creation and verification for NetGuard authentication.

Algorithm : HS256
Expiry    : 1 hour  (configurable via JWT_EXPIRY_HOURS env var)
Secret    : process.env.JWT_SECRET  — MUST be set in production

Usage
-----
    from auth.jwt_handler import create_token, verify_token_payload

    token   = create_token(user_id="abc", email="a@b.com", role="admin")
    payload = verify_token_payload(token)  # raises on invalid/expired
"""

import os
import logging
from datetime import datetime, timezone, timedelta

import jwt  # PyJWT

logger = logging.getLogger(__name__)

# Read from environment — never hardcode in source.
JWT_SECRET       = os.environ.get("JWT_SECRET", "CHANGE_ME_BEFORE_PRODUCTION")
JWT_ALGORITHM    = "HS256"
JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "1"))


def create_token(*, user_id: str, email: str, role: str) -> str:
    """
    Sign and return a JWT containing the user's identity and role.

    Parameters
    ----------
    user_id : str – Unique user identifier (UUID)
    email   : str – User's email address
    role    : str – admin | analyst | viewer

    Returns
    -------
    str – Signed JWT string

    Notes
    -----
    Payload keys:
      sub   – subject (user_id)
      email – user email
      role  – RBAC role
      iat   – issued-at timestamp (UTC)
      exp   – expiry timestamp   (UTC, iat + JWT_EXPIRY_HOURS)
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub":   user_id,
        "email": email,
        "role":  role,
        "iat":   now,
        "exp":   now + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    logger.debug("[jwt] Created token for user=%s role=%s", email, role)
    return token


def verify_token_payload(token: str) -> dict:
    """
    Decode and validate a JWT, returning its payload.

    Parameters
    ----------
    token : str – Raw JWT string (without 'Bearer ' prefix)

    Returns
    -------
    dict – Decoded payload: {sub, email, role, iat, exp}

    Raises
    ------
    jwt.ExpiredSignatureError – Token has passed its expiry time.
    jwt.InvalidTokenError     – Token is malformed or signature is wrong.
    """
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    return payload
