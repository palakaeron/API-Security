import os

from app.auth import issue_secure_token, issue_vulnerable_token
from app.main import app
from fastapi.testclient import TestClient

os.environ["LAB_SECURE_JWT_SECRET"] = "test-only-synthetic-secure-secret"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_vulnerable_user_route_allows_cross_user_access() -> None:
    token = issue_vulnerable_token("alice", "user")

    response = TestClient(app).get("/vuln/users/bob", headers=_auth(token))

    assert response.status_code == 200
    assert response.json()["id"] == "bob"


def test_secure_user_route_rejects_cross_user_access() -> None:
    token = issue_secure_token("alice", "user", os.environ["LAB_SECURE_JWT_SECRET"])

    response = TestClient(app).get("/secure/users/bob", headers=_auth(token))

    assert response.status_code == 403


def test_secure_admin_route_requires_admin_role() -> None:
    token = issue_secure_token("alice", "user", os.environ["LAB_SECURE_JWT_SECRET"])

    response = TestClient(app).get("/secure/admin/audit", headers=_auth(token))

    assert response.status_code == 403


def test_internal_shadow_endpoint_is_not_in_openapi_schema() -> None:
    schema = TestClient(app).get("/openapi.json").json()

    assert "/internal/diagnostics" not in schema["paths"]
    assert TestClient(app).get("/internal/diagnostics").status_code == 200


def test_vulnerable_graphql_allows_introspection() -> None:
    response = TestClient(app).post(
        "/vuln/graphql", json={"query": "{ __schema { queryType { name } } }"}
    )

    assert response.status_code == 200
    assert response.json()["data"]["__schema"]["queryType"]["name"] == "Query"


def test_secure_graphql_rejects_introspection() -> None:
    response = TestClient(app).post(
        "/secure/graphql", json={"query": "{ __schema { queryType { name } } }"}
    )

    assert response.status_code == 403
