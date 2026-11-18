"""Shared SQLAlchemy engine, session, and declarative base configuration."""

from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    """Base class for all runtime database models."""


SQLITE_BUSY_TIMEOUT_MS = 5_000


def _engine_kwargs(database_url: str) -> dict[str, object]:
    if database_url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {}


@lru_cache(maxsize=8)
def get_engine(database_url: str | None = None) -> Engine:
    """Return a shared engine for the configured or supplied database URL."""

    url = database_url or get_settings().database_url
    engine = create_engine(url, **_engine_kwargs(url))
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
            cursor.close()

    return engine


@lru_cache(maxsize=8)
def get_session_factory(database_url: str | None = None) -> sessionmaker[Session]:
    """Return a reusable session factory bound to the shared engine."""

    return sessionmaker(bind=get_engine(database_url), autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that opens and reliably closes a database session."""

    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
