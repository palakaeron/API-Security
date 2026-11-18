"""Tests for M3 discovery features: diff logic, traffic endpoint, and error handling.

Coverage:
- Shadow detection (traffic endpoint absent from declared spec)
- Zombie detection (deprecated declared endpoint that also appears in traffic)
- Empty diff when traffic matches spec exactly
- /discovery/traffic endpoint (records observations as traffic rows)
- /discovery/diff/{api_id} endpoint (returns shadow/zombie JSON)
- /discovery/import 422 on unknown format
- /discovery/import 422 on malformed OpenAPI content
- Duplicate import idempotency (second import of same endpoints is a no-op)
"""

from __future__ import annotations

import json
import types

import pytest
from app.discovery.diff import diff_endpoints
from app.discovery.models import DiscoveredEndpoint
from app.discovery.persistence import import_endpoints, metadata
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def mem_engine():
    """In-memory SQLite engine with the endpoint table pre-created."""
    engine = create_engine("sqlite://")
    metadata.create_all(engine)
    return engine


def _ep(path: str, method: str, *, deprecated: bool = False) -> DiscoveredEndpoint:
    """Helper to build a minimal DiscoveredEndpoint."""
    return DiscoveredEndpoint(
        path=path,
        method=method,
        parameters=[],
        request_schema=None,
        response_schemas={},
        auth_scheme="none",
        deprecated=deprecated,
    )


# ── Diff logic unit tests ─────────────────────────────────────────────────────


class TestDiffEndpoints:
    def test_shadow_endpoint_detected_when_in_traffic_but_not_in_spec(
        self, mem_engine
    ) -> None:
        api_id = 1
        # Declare two spec endpoints.
        import_endpoints(mem_engine, api_id, [_ep("/users/{id}", "GET")], "spec")
        # Record traffic that includes a third, undeclared endpoint.
        import_endpoints(
            mem_engine,
            api_id,
            [_ep("/users/{id}", "GET"), _ep("/internal/diagnostics", "GET")],
            "traffic",
        )

        result = diff_endpoints(mem_engine, api_id)

        shadow_paths = {(e.method, e.path) for e in result.shadow}
        assert ("GET", "/internal/diagnostics") in shadow_paths
        assert ("GET", "/users/{id}") not in shadow_paths

    def test_zombie_endpoint_detected_when_deprecated_spec_endpoint_in_traffic(
        self, mem_engine
    ) -> None:
        api_id = 2
        # Declare a deprecated spec endpoint alongside a live one.
        import_endpoints(
            mem_engine,
            api_id,
            [
                _ep("/v1/users/{id}", "GET", deprecated=True),
                _ep("/v2/users/{id}", "GET"),
            ],
            "spec",
        )
        # Traffic hits the deprecated endpoint.
        import_endpoints(mem_engine, api_id, [_ep("/v1/users/{id}", "GET")], "traffic")

        result = diff_endpoints(mem_engine, api_id)

        zombie_paths = {(e.method, e.path) for e in result.zombie}
        assert ("GET", "/v1/users/{id}") in zombie_paths
        # Non-deprecated endpoint must NOT appear in zombie list.
        assert ("GET", "/v2/users/{id}") not in zombie_paths

    def test_empty_diff_when_all_traffic_is_declared(self, mem_engine) -> None:
        api_id = 3
        endpoints = [_ep("/orders/{id}", "GET"), _ep("/orders", "POST")]
        import_endpoints(mem_engine, api_id, endpoints, "spec")
        import_endpoints(mem_engine, api_id, endpoints, "traffic")

        result = diff_endpoints(mem_engine, api_id)

        assert result.shadow == []
        assert result.zombie == []
        assert not result.has_findings

    def test_no_traffic_produces_empty_diff(self, mem_engine) -> None:
        api_id = 4
        import_endpoints(mem_engine, api_id, [_ep("/health", "GET")], "spec")

        result = diff_endpoints(mem_engine, api_id)

        assert result.shadow == []
        assert result.zombie == []

    def test_deprecated_endpoint_only_zombie_if_in_traffic(self, mem_engine) -> None:
        """A deprecated declared endpoint that is NOT in traffic is NOT a zombie."""
        api_id = 5
        import_endpoints(
            mem_engine, api_id, [_ep("/v1/legacy", "GET", deprecated=True)], "spec"
        )
        # No traffic recorded.

        result = diff_endpoints(mem_engine, api_id)

        assert result.zombie == []

    def test_diff_returns_correct_api_id(self, mem_engine) -> None:
        api_id = 99
        result = diff_endpoints(mem_engine, api_id)
        assert result.api_id == api_id

    def test_shadow_and_zombie_can_coexist(self, mem_engine) -> None:
        api_id = 6
        import_endpoints(
            mem_engine,
            api_id,
            [_ep("/v1/old", "GET", deprecated=True), _ep("/v2/current", "GET")],
            "spec",
        )
        import_endpoints(
            mem_engine,
            api_id,
            [_ep("/v1/old", "GET"), _ep("/internal/hidden", "POST")],
            "traffic",
        )

        result = diff_endpoints(mem_engine, api_id)

        assert any(e.path == "/v1/old" for e in result.zombie)
        assert any(e.path == "/internal/hidden" for e in result.shadow)


# ── Duplicate import idempotency ──────────────────────────────────────────────


class TestImportIdempotency:
    def test_importing_same_endpoints_twice_does_not_duplicate(self, mem_engine) -> None:
        api_id = 10
        eps = [_ep("/users/{id}", "GET"), _ep("/users", "POST")]
        first = import_endpoints(mem_engine, api_id, eps, "spec")
        second = import_endpoints(mem_engine, api_id, eps, "spec")

        # The second import should insert 0 rows (ON CONFLICT DO NOTHING).
        assert first == 2
        assert second == 0

    def test_partial_duplicate_only_inserts_new_rows(self, mem_engine) -> None:
        api_id = 11
        import_endpoints(mem_engine, api_id, [_ep("/a", "GET")], "spec")
        inserted = import_endpoints(
            mem_engine, api_id, [_ep("/a", "GET"), _ep("/b", "DELETE")], "spec"
        )
        assert inserted == 1  # only /b is new


# ── API endpoint tests (via TestClient) ──────────────────────────────────────


@pytest.fixture
def client(tmp_path, monkeypatch):
    """FastAPI TestClient with the settings DATABASE_URL pointed at a temp file.

    The endpoint functions reference the module-level ``settings`` object at
    call time, so we patch ``app.main.settings`` directly after import.
    """
    db_path = tmp_path / "test.db"
    db_url = f"sqlite:///{db_path}"

    # Build the tables in the temp DB.
    from app.discovery.persistence import metadata as disc_meta  # noqa: PLC0415
    from sqlalchemy import create_engine as _ce

    engine = _ce(db_url)
    disc_meta.create_all(engine)

    from app.models import Api, Project, User
    from sqlalchemy.orm import Session

    with Session(engine) as session:
        owner = User(email="discovery-owner@example.test", password_hash="synthetic-hash")
        project = Project(name="Discovery Project", owner=owner)
        session.add(project)
        session.flush()
        session.add_all(
            [
                Api(id=api_id, project_id=project.id, name=f"Discovery API {api_id}")
                for api_id in range(1, 6)
            ]
        )
        session.commit()

    # Patch the module-level settings object so all endpoint functions use the
    # temp DB URL when they call create_engine(settings.database_url).
    import app.main as main_module

    fake_settings = types.SimpleNamespace(
        database_url=db_url,
        cors_origin_list=["http://127.0.0.1:5173"],
    )
    monkeypatch.setattr(main_module, "settings", fake_settings)

    from app.main import app as fastapi_app

    return TestClient(fastapi_app), db_url


class TestTrafficEndpoint:
    def test_post_traffic_records_observations(self, client) -> None:
        tc, db_url = client
        payload = {
            "api_id": 1,
            "observations": [
                {"method": "GET", "path": "/v1/users/{user_id}"},
                {"method": "GET", "path": "/internal/diagnostics"},
            ],
        }
        response = tc.post("/discovery/traffic", json=payload)

        assert response.status_code == 200
        assert response.json()["recorded"] == 2

    def test_post_traffic_duplicate_is_idempotent(self, client) -> None:
        tc, _ = client
        payload = {
            "api_id": 2,
            "observations": [{"method": "POST", "path": "/vuln/auth/token"}],
        }
        r1 = tc.post("/discovery/traffic", json=payload)
        r2 = tc.post("/discovery/traffic", json=payload)

        assert r1.status_code == 200
        assert r2.status_code == 200
        # Second call records 0 (duplicate suppressed).
        assert r2.json()["recorded"] == 0

    def test_post_traffic_rejects_path_without_leading_slash(self, client) -> None:
        tc, _ = client
        payload = {
            "api_id": 3,
            "observations": [{"method": "GET", "path": "no-leading-slash"}],
        }
        response = tc.post("/discovery/traffic", json=payload)
        assert response.status_code == 422

    def test_post_traffic_rejects_unsupported_method(self, client) -> None:
        tc, _ = client
        payload = {
            "api_id": 4,
            "observations": [{"method": "CONNECT", "path": "/foo"}],
        }
        response = tc.post("/discovery/traffic", json=payload)
        assert response.status_code == 422

    def test_post_traffic_rejects_empty_observations(self, client) -> None:
        tc, _ = client
        response = tc.post("/discovery/traffic", json={"api_id": 5, "observations": []})
        assert response.status_code == 422


class TestDiffEndpoint:
    def _seed(self, db_url: str) -> None:
        """Populate spec and traffic rows for api_id=1."""
        from sqlalchemy import create_engine as _ce

        engine = _ce(db_url)
        # Declared spec endpoints.
        import_endpoints(
            engine,
            1,
            [
                _ep("/vuln/users/{user_id}", "GET"),
                _ep("/secure/users/{user_id}", "GET"),
                _ep("/v1/users/{user_id}", "GET", deprecated=True),
            ],
            "spec",
        )
        # Traffic hits the deprecated + an undeclared endpoint.
        import_endpoints(
            engine,
            1,
            [
                _ep("/vuln/users/{user_id}", "GET"),
                _ep("/v1/users/{user_id}", "GET"),
                _ep("/internal/diagnostics", "GET"),
            ],
            "traffic",
        )

    def test_diff_endpoint_returns_shadow_and_zombie(self, client) -> None:
        tc, db_url = client
        self._seed(db_url)

        response = tc.get("/discovery/diff/1")

        assert response.status_code == 200
        body = response.json()
        assert body["api_id"] == 1
        shadow_paths = {e["path"] for e in body["shadow"]}
        zombie_paths = {e["path"] for e in body["zombie"]}
        assert "/internal/diagnostics" in shadow_paths
        assert "/vuln/users/{user_id}" not in shadow_paths
        assert "/v1/users/{user_id}" in zombie_paths

    def test_diff_endpoint_empty_when_no_traffic(self, client) -> None:
        tc, db_url = client
        response = tc.get("/discovery/diff/999")  # unknown api_id
        assert response.status_code == 200
        body = response.json()
        assert body["shadow"] == []
        assert body["zombie"] == []


class TestImportEndpoint:
    def test_import_returns_422_for_unknown_format(self, client) -> None:
        tc, _ = client
        payload = {"api_id": 1, "format": "swagger2", "content": "{}"}
        response = tc.post("/discovery/import", json=payload)
        assert response.status_code == 422

    def test_import_returns_422_for_malformed_openapi(self, client) -> None:
        tc, _ = client
        payload = {"api_id": 1, "format": "openapi", "content": "openapi: 2.0\npaths: {}"}
        response = tc.post("/discovery/import", json=payload)
        assert response.status_code == 422

    def test_import_openapi_success(self, client) -> None:
        tc, _ = client
        spec = json.dumps(
            {
                "openapi": "3.0.3",
                "paths": {
                    "/users": {"get": {"responses": {"200": {"description": "ok"}}}},
                },
            }
        )
        payload = {"api_id": 1, "format": "openapi", "content": spec}
        response = tc.post("/discovery/import", json=payload)
        assert response.status_code == 200
        assert response.json()["imported"] == 1
        assert response.json()["source"] == "spec"

    def test_import_is_idempotent(self, client) -> None:
        tc, _ = client
        spec = json.dumps(
            {
                "openapi": "3.0.3",
                "paths": {
                    "/items": {"post": {"responses": {"201": {"description": "created"}}}},
                },
            }
        )
        payload = {"api_id": 2, "format": "openapi", "content": spec}
        r1 = tc.post("/discovery/import", json=payload)
        r2 = tc.post("/discovery/import", json=payload)
        assert r1.json()["imported"] == 1
        assert r2.json()["imported"] == 0  # duplicate suppressed
