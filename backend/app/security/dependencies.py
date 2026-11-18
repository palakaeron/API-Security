"""Reusable FastAPI dependencies for authenticated user lookup."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import User
from app.security.passwords import decode_access_token

_bearer_scheme = HTTPBearer(auto_error=False)
DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    db: DbSession,
) -> User:
    """Verify a bearer JWT and resolve its subject to an existing user."""

    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or missing authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    settings = get_settings()
    secret = settings.jwt_secret
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized
    if secret is None or len(secret.encode("utf-8")) < 32:
        raise unauthorized
    try:
        claims = decode_access_token(credentials.credentials, secret)
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.isdecimal() or int(subject) <= 0:
            raise unauthorized
    except Exception:
        raise unauthorized from None

    user = db.get(User, int(subject))
    if user is None:
        raise unauthorized
    return user
