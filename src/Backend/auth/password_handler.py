"""
password_handler.py
===================
bcrypt password hashing and verification for NetGuard user accounts.

Salt rounds : 12  (configurable via BCRYPT_ROUNDS env var)

Usage
-----
    from auth.password_handler import hash_password, check_password

    hashed  = hash_password("my_secret_password")
    is_ok   = check_password("my_secret_password", hashed)  # True
"""

import os
import logging

import bcrypt

logger = logging.getLogger(__name__)

BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))


def hash_password(plain_password: str) -> str:
    """
    Hash a plain-text password using bcrypt.

    Parameters
    ----------
    plain_password : str – The user's raw password

    Returns
    -------
    str – The bcrypt hash string (60 characters, includes salt & cost factor)

    Notes
    -----
    Uses BCRYPT_ROUNDS (default 12) cost factor. Higher values increase
    resistance to brute-force but also increase hashing time (~250 ms at 12).
    """
    salt   = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    logger.debug("[password] Hashed password with %d rounds", BCRYPT_ROUNDS)
    return hashed.decode("utf-8")


def check_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a stored bcrypt hash.

    Parameters
    ----------
    plain_password  : str – The password provided at login
    hashed_password : str – The stored bcrypt hash

    Returns
    -------
    bool – True if the password matches, False otherwise

    Notes
    -----
    Uses constant-time comparison internally to prevent timing attacks.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception as exc:
        logger.error("[password] checkpw failed: %s", exc)
        return False
