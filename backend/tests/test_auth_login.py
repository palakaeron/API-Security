import jwt
import pytest
from app.database import Base, get_db, get_engine
from app.main import app
from app.models import User
from app.security.passwords import create_access_token, decode_access_token, hash_password
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture
def login_client(tmp_path):
    engine = get_engine(f"sqlite:///{tmp_path / 'login.db'}")
    Base.metadata.create_all(engine)

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        yield TestClient(app), engine
    finally:
        app.dependency_overrides.pop(get_db, None)


def _configure_signing(monkeypatch, secret: str, minutes: int = 5) -> None:
    monkeypatch.setattr(
        "app.routers.auth.get_settings",
        lambda: type("Settings", (), {"jwt_secret": secret, "jwt_access_token_minutes": minutes})(),
    )


def test_login_returns_signed_token(login_client, monkeypatch) -> None:
    client, engine = login_client
    secret = "test-signing-secret-with-at-least-32-bytes"
    _configure_signing(monkeypatch, secret)
    with Session(engine) as db:
        db.add(User(email="login@example.test", password_hash=hash_password("correct password")))
        db.commit()

    response = client.post(
        "/auth/login",
        json={"email": " LOGIN@example.test ", "password": "correct password"},
    )
    assert response.status_code == 200
    body = response.json()
    claims = decode_access_token(body["access_token"], secret)
    assert claims["sub"] == "1"
    assert "iat" in claims and "exp" in claims
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 300
    assert "password" not in body and "password_hash" not in body


@pytest.mark.parametrize(
    ("email", "password"),
    [("absent@example.test", "correct password"), ("known@example.test", "wrong password")],
)
def test_login_uses_generic_401(login_client, email, password) -> None:
    client, engine = login_client
    with Session(engine) as db:
        db.add(User(email="known@example.test", password_hash=hash_password("correct password")))
        db.commit()
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid email or password"


def test_token_decoder_rejects_expired_signature_and_malformed_tokens() -> None:
    secret = "test-signing-secret-with-at-least-32-bytes"
    expired = create_access_token(4, secret, -1)
    wrong_signature = create_access_token(4, "another-signing-secret-with-32-bytes", 5)
    for token, expected_error in (
        (expired, jwt.ExpiredSignatureError),
        (wrong_signature, jwt.InvalidSignatureError),
        ("not.a.jwt", jwt.DecodeError),
    ):
        with pytest.raises(expected_error):
            decode_access_token(token, secret)
