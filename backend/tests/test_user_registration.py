from __future__ import annotations

import pytest
from app.database import Base, get_db, get_engine
from app.main import app
from app.models import User
from app.security.passwords import verify_password
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture
def auth_client(tmp_path):
    engine = get_engine(f"sqlite:///{tmp_path / 'auth.db'}")
    Base.metadata.create_all(engine)

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        yield TestClient(app), engine
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_registration_hashes_password_and_returns_public_user(auth_client) -> None:
    client, engine = auth_client

    response = client.post(
        "/auth/register",
        json={"email": "  New.User@Example.test ", "password": "correct horse battery staple"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "new.user@example.test"
    assert "password" not in data
    assert "password_hash" not in data
    assert "argon2" not in data

    with Session(engine) as db:
        user = db.query(User).one()
        assert user.email == "new.user@example.test"
        assert user.password_hash != "correct horse battery staple"
        assert user.password_hash.startswith("$argon2id$")
        assert verify_password("correct horse battery staple", user.password_hash)
        assert not verify_password("wrong password", user.password_hash)


def test_duplicate_email_is_rejected_without_creating_second_user(auth_client) -> None:
    client, engine = auth_client
    payload = {"email": "duplicate@example.test", "password": "a sufficiently long password"}

    assert client.post("/auth/register", json=payload).status_code == 201
    duplicate = client.post(
        "/auth/register",
        json={**payload, "email": "DUPLICATE@example.test"},
    )

    assert duplicate.status_code == 409
    with Session(engine) as db:
        assert db.query(User).count() == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "not-an-email", "password": "a sufficiently long password"},
        {"email": "missing-domain@example", "password": "a sufficiently long password"},
        {"email": "valid@example.test", "password": "short"},
        {"email": "valid@example.test", "password": ""},
    ],
)
def test_invalid_registration_input_is_rejected(auth_client, payload) -> None:
    client, engine = auth_client

    response = client.post("/auth/register", json=payload)

    assert response.status_code == 422
    with Session(engine) as db:
        assert db.query(User).count() == 0
