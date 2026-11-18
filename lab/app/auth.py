"""Authentication helpers for controlled lab behavior only."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import HTTPException, Request, status

LAB_VULNERABLE_JWT_SECRET = "lab-only-weak-secret"
SECURE_ISSUER = "api-security-lab"
SECURE_AUDIENCE = "api-security-lab-client"


def issue_vulnerable_token(subject: str, role: str) -> str:
    """Issue intentionally weak lab-only HS256 tokens with excessive expiry."""
    payload = {
        "sub": subject,
        "role": role,
        "exp": datetime.now(UTC) + timedelta(days=3650),
    }
    return jwt.encode(payload, LAB_VULNERABLE_JWT_SECRET, algorithm="HS256")


def issue_secure_token(subject: str, role: str, secret: str) -> str:
    payload = {
        "sub": subject,
        "role": role,
        "iss": SECURE_ISSUER,
        "aud": SECURE_AUDIENCE,
        "exp": datetime.now(UTC) + timedelta(minutes=15),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="valid bearer token required"
        )
    return token


def vulnerable_identity(request: Request) -> dict[str, str]:
    token = _bearer_token(request)
    try:
        return jwt.decode(token, LAB_VULNERABLE_JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token"
        ) from error


def secure_identity(request: Request) -> dict[str, str]:
    secret = os.environ.get("LAB_SECURE_JWT_SECRET")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="secure lab secret unset"
        )
    token = _bearer_token(request)
    try:
        return jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            issuer=SECURE_ISSUER,
            audience=SECURE_AUDIENCE,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token"
        ) from error
