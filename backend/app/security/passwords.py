"""Password hashing helpers for platform authentication."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_PASSWORD_HASHER = PasswordHasher()
JWT_ALGORITHM = "HS256"


def create_access_token(user_id: int, secret: str, expires_minutes: int) -> str:
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("JWT signing secret must contain at least 32 bytes")
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    return jwt.encode(claims, secret, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str, secret: str) -> dict[str, object]:
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("JWT signing secret must contain at least 32 bytes")
    return jwt.decode(
        token,
        secret,
        algorithms=[JWT_ALGORITHM],
        options={"require": ["sub", "iat", "exp"]},
    )


def hash_password(password: str) -> str:
    """Hash a password with Argon2id using the library's maintained defaults."""

    return _PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password without exposing hashing or verification errors."""

    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False
