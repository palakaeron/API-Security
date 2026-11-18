from app.discovery.models import DiscoveredEndpoint
from app.discovery.persistence import import_endpoints, list_endpoints, metadata
from sqlalchemy import create_engine


def test_persistence_preserves_source_and_normalized_fields() -> None:
    engine = create_engine("sqlite://")
    metadata.create_all(engine)
    endpoint = DiscoveredEndpoint(
        "/users/{id}", "GET", [{"in": "path", "name": "id"}], None, {"200": {}}, "bearer_jwt", True
    )

    assert import_endpoints(engine, 7, [endpoint], "spec") == 1
    rows = list_endpoints(engine, 7)
    assert rows[0]["source"] == "spec"
    assert rows[0]["auth_scheme"] == "bearer_jwt"
    assert rows[0]["deprecated"] is True
