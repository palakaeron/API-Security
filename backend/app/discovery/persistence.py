from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.database import Base
from app.discovery.models import DiscoveredEndpoint
from app.models import Endpoint

metadata = Base.metadata
endpoint_table = Endpoint.__table__


def import_endpoints(
    engine: Engine, api_id: int, endpoints: list[DiscoveredEndpoint], source: str
) -> int:
    """Insert or update discovered endpoints using shared model metadata."""
    if source not in {"spec", "postman", "traffic"}:
        raise ValueError("source must be spec, postman, or traffic")
    if not endpoints:
        return 0

    if source in {"spec", "postman"}:
        return _insert_declared(engine, api_id, endpoints, source)
    return _insert_traffic(engine, api_id, endpoints)


def _insert_declared(
    engine: Engine, api_id: int, endpoints: list[DiscoveredEndpoint], source: str
) -> int:
    rows = [
        {
            "api_id": api_id,
            "path": item.path,
            "method": item.method,
            "auth_scheme": item.auth_scheme,
            "source": source,
            "parameters": item.parameters,
            "request_schema": item.request_schema,
            "response_schemas": item.response_schemas,
            "deprecated": item.deprecated,
            "seen_in_traffic": False,
        }
        for item in endpoints
    ]
    stmt = sqlite_insert(endpoint_table).values(rows).on_conflict_do_nothing()
    with engine.begin() as connection:
        before_count = connection.execute(
            select(func.count())
            .select_from(endpoint_table)
            .where(endpoint_table.c.api_id == api_id)
        ).scalar_one()
        connection.execute(stmt)
        after_count = connection.execute(
            select(func.count())
            .select_from(endpoint_table)
            .where(endpoint_table.c.api_id == api_id)
        ).scalar_one()
    return after_count - before_count


def _insert_traffic(engine: Engine, api_id: int, endpoints: list[DiscoveredEndpoint]) -> int:
    rows = [
        {
            "api_id": api_id,
            "path": item.path,
            "method": item.method,
            "auth_scheme": item.auth_scheme,
            "source": "traffic",
            "parameters": item.parameters,
            "request_schema": item.request_schema,
            "response_schemas": item.response_schemas,
            "deprecated": item.deprecated,
            "seen_in_traffic": True,
        }
        for item in endpoints
    ]
    stmt = (
        sqlite_insert(endpoint_table)
        .values(rows)
        .on_conflict_do_update(
            index_elements=["api_id", "path", "method"],
            set_={"seen_in_traffic": True},
        )
    )
    with engine.begin() as connection:
        before_count = connection.execute(
            select(func.count())
            .select_from(endpoint_table)
            .where(endpoint_table.c.api_id == api_id)
        ).scalar_one()
        connection.execute(stmt)
        after_count = connection.execute(
            select(func.count())
            .select_from(endpoint_table)
            .where(endpoint_table.c.api_id == api_id)
        ).scalar_one()
    return after_count - before_count


def list_endpoints(engine: Engine, api_id: int) -> list[dict[str, Any]]:
    with engine.connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                select(endpoint_table).where(endpoint_table.c.api_id == api_id)
            ).mappings()
        ]
