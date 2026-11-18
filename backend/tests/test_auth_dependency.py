import pytest
from app.database import Base, get_db, get_engine
from app.main import app
from app.models import User
from app.security.dependencies import get_current_user
from app.security.passwords import create_access_token
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture
def protected_client(tmp_path, monkeypatch):
    engine = get_engine(f"sqlite:///{tmp_path / 'dependency.db'}")
    Base.metadata.create_all(engine)
    secret = "dependency-test-secret-with-more-than-32-bytes"
    monkeypatch.setattr(
        "app.security.dependencies.get_settings",
        lambda: type("Settings", (), {"jwt_secret": secret})(),
    )

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    probe = FastAPI()
    probe.dependency_overrides.update(app.dependency_overrides)
    @probe.get("/probe")
    # FastAPI dependency defaults are intentional here.
    # noqa: B008
    def protected_probe(user: User = Depends(get_current_user)):  # noqa: B008
        return {"id": user.id, "email": user.email}
    try:
        yield TestClient(probe), engine, secret
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_dependency_accepts_valid_bearer_and_resolves_user(protected_client) -> None:
    client, engine, secret = protected_client
    with Session(engine) as db:
        user = User(email="dependency@example.test", password_hash="opaque-hash")
        db.add(user)
        db.commit()
        user_id = user.id
    token = create_access_token(user_id, secret, 5)
    response = client.get("/probe", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"id": user_id, "email": "dependency@example.test"}


@pytest.mark.parametrize(
    "authorization",
    [None, "Basic abc", "Bearer", "Bearer not.a.jwt", "Bearer malformed"],
)
def test_dependency_rejects_missing_or_malformed_authorization(
    protected_client, authorization
) -> None:
    client, _, _ = protected_client
    headers = {} if authorization is None else {"Authorization": authorization}
    response = client.get("/probe", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid or missing authentication token"


def test_dependency_rejects_expired_and_wrong_signature_tokens(protected_client) -> None:
    client, _, secret = protected_client
    expired = create_access_token(1, secret, -1)
    invalid_signature = create_access_token(1, "other-secret-that-is-also-long-enough-32", 5)
    for token in (expired, invalid_signature):
        response = client.get("/probe", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401


def test_dependency_rejects_deleted_or_nonexistent_user(protected_client) -> None:
    client, engine, secret = protected_client
    with Session(engine) as db:
        user = User(email="deleted@example.test", password_hash="opaque-hash")
        db.add(user)
        db.commit()
        user_id = user.id
        db.delete(user)
        db.commit()
    token = create_access_token(user_id, secret, 5)
    response = client.get("/probe", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_dependency_rejects_non_numeric_subject(protected_client) -> None:
    client, _, secret = protected_client
    import jwt

    token = jwt.encode({"sub": "user", "iat": 1, "exp": 4_000_000_000}, secret, algorithm="HS256")
    assert client.get("/probe", headers={"Authorization": f"Bearer {token}"}).status_code == 401
