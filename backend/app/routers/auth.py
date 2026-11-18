from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import User
from app.routers.schemas import AccessTokenRead, UserLogin, UserRead, UserRegister
from app.security.passwords import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])
DbSession = Annotated[Session, Depends(get_db)]


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserRegister, db: DbSession) -> User:
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password.get_secret_value()),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if "users.email" in str(exc).lower() or "uq_users_email" in str(exc).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="an account with this email already exists",
            ) from None
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="registration could not be completed",
        ) from None
    db.refresh(user)
    return user


@router.post("/login", response_model=AccessTokenRead)
def login(payload: UserLogin, db: DbSession) -> AccessTokenRead:
    user = db.query(User).filter(User.email == payload.email).one_or_none()
    password = payload.password.get_secret_value()
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    settings = get_settings()
    if settings.jwt_secret is None or len(settings.jwt_secret.encode("utf-8")) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication is not configured",
        )
    try:
        token = create_access_token(
            user.id, settings.jwt_secret, settings.jwt_access_token_minutes
        )
    except ValueError:
        raise HTTPException(status_code=503, detail="authentication is not configured") from None
    return AccessTokenRead(
        access_token=token,
        expires_in=settings.jwt_access_token_minutes * 60,
    )
