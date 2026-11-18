import json

import pytest
from app.database import Base, get_db, get_engine
from app.main import app
from app.models import User
from app.routers.schemas import ApiCreate, ApiUpdate
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.orm import Session


@pytest.fixture
def management_client(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'management.db'}"
    engine = get_engine(db_url)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(User(email="owner@example.test", password_hash="synthetic-hash"))
        session.commit()

    def override_db():
        session = Session(engine)
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_project_api_discovery_workflow(management_client: TestClient) -> None:
    project_response = management_client.post(
        "/projects", json={"name": "Inventory Project", "owner_id": 1}
    )
    assert project_response.status_code == 201
    project = project_response.json()
    assert project["name"] == "Inventory Project"
    assert project["owner_id"] == 1

    api_response = management_client.post(
        f"/projects/{project['id']}/apis",
        json={
            "name": "Users API",
            "version": "1.0",
            "base_url": "http://127.0.0.1:8102",
            "description": "Synthetic users service",
            "environment": "local",
        },
    )
    assert api_response.status_code == 201
    api = api_response.json()
    assert api["project_id"] == project["id"]
    assert api["base_url"] == "http://127.0.0.1:8102"

    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/users/{user_id}": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
    }
    import_response = management_client.post(
        f"/apis/{api['id']}/discovery/import",
        json={"format": "openapi", "content": json.dumps(spec)},
    )
    assert import_response.status_code == 200
    assert import_response.json() == {
        "api_id": api["id"],
        "imported": 1,
        "source": "spec",
    }

    inventory_response = management_client.get(f"/apis/{api['id']}/endpoints")
    assert inventory_response.status_code == 200
    inventory = inventory_response.json()
    assert inventory["total"] == 1
    assert inventory["items"][0]["path"] == "/users/{user_id}"


def test_project_and_api_validation_and_cascade_delete(management_client: TestClient) -> None:
    missing_owner = management_client.post(
        "/projects", json={"name": "Invalid", "owner_id": 999}
    )
    assert missing_owner.status_code == 404

    missing_project = management_client.post(
        "/projects/999/apis", json={"name": "Orphan API"}
    )
    assert missing_project.status_code == 404

    project = management_client.post(
        "/projects", json={"name": "Delete Me", "owner_id": 1}
    ).json()
    invalid_url = management_client.post(
        f"/projects/{project['id']}/apis",
        json={"name": "Invalid URL API", "base_url": "ftp://example.test"},
    )
    assert invalid_url.status_code == 422

    api = management_client.post(
        f"/projects/{project['id']}/apis", json={"name": "Cascade API"}
    ).json()
    deleted = management_client.delete(f"/projects/{project['id']}")
    assert deleted.status_code == 204
    assert management_client.get(f"/projects/{project['id']}").status_code == 404
    assert management_client.get(f"/apis/{api['id']}").status_code == 404


@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:8101",
        "https://api.example.test",
    ],
)
def test_normal_http_urls_are_accepted(base_url: str) -> None:
    assert ApiCreate(name="Valid API", base_url=base_url).base_url is not None
    assert ApiUpdate(base_url=base_url).base_url is not None


@pytest.mark.parametrize(
    "base_url",
    [
        "http://test-user@127.0.0.1:8101",
        "http://:test-password@127.0.0.1:8101",
        "http://test-user:test-password@127.0.0.1:8101",
    ],
)
def test_credential_bearing_urls_are_rejected_without_echoing_values(base_url: str) -> None:
    with pytest.raises(ValidationError) as create_error:
        ApiCreate(name="Invalid API", base_url=base_url)
    with pytest.raises(ValidationError) as update_error:
        ApiUpdate(base_url=base_url)

    for error in (create_error.value, update_error.value):
        assert "must not contain credentials" in str(error)
        assert "test-user" not in str(error)
        assert "test-password" not in str(error)


def test_api_update_rejects_credentials_before_database_write(
    management_client: TestClient,
) -> None:
    project = management_client.post(
        "/projects", json={"name": "Update Validation", "owner_id": 1}
    ).json()
    api = management_client.post(
        f"/projects/{project['id']}/apis",
        json={"name": "Protected API", "base_url": "https://api.example.test"},
    ).json()

    response = management_client.patch(
        f"/apis/{api['id']}",
        json={"base_url": "https://test-user:test-password@api.example.test"},
    )

    assert response.status_code == 422
    assert "test-user" not in response.text
    assert "test-password" not in response.text
    unchanged = management_client.get(f"/apis/{api['id']}").json()
    assert unchanged["base_url"] == "https://api.example.test"
