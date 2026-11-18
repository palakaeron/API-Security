from __future__ import annotations

from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Engine,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.discovery.models import DiscoveredEndpoint

metadata = MetaData()
endpoint_table = Table(
    "endpoints",
    metadata,
    # This definition mirrors migrations 0001–0003 and remains SQLite/PostgreSQL portable.
    Column("id", Integer, primary_key=True),
    Column("api_id", Integer, nullable=False),
    Column("path", String(2048), nullable=False),
    Column("method", String(10), nullable=False),
    Column("auth_scheme", String(100)),
    Column("source", String(32), nullable=False),
    Column("parameters", JSON),
    Column("request_schema", JSON),
    Column("response_schemas", JSON),
    Column("deprecated", Boolean, nullable=False, server_default="0"),
    Column("seen_in_traffic", Boolean, nullable=False, server_default="0"),
    UniqueConstraint("api_id", "path", "method", name="uq_endpoints_api_path_method"),
)


def import_endpoints(
    engine: Engine, api_id: int, endpoints: list[DiscoveredEndpoint], source: str
) -> int:
    """Insert or update discovered endpoints.

    Behaviour by source:
    - ``spec`` / ``postman``: insert new rows only (skip duplicates).
    - ``traffic``: insert new rows; for endpoints that already exist in the
      declared spec, update ``seen_in_traffic=True`` on the existing row.
      This preserves the original ``source`` value while still recording that
      the endpoint was observed in live traffic — which is what the zombie
      detector needs.

    Returns the number of new rows actually inserted (updates not counted).
    """
    if source not in {"spec", "postman", "traffic"}:
        raise ValueError("source must be spec, postman, or traffic")
    if not endpoints:
        return 0

    if source in {"spec", "postman"}:
        return _insert_declared(engine, api_id, endpoints, source)
    else:
        return _insert_traffic(engine, api_id, endpoints)


def _insert_declared(
    engine: Engine, api_id: int, endpoints: list[DiscoveredEndpoint], source: str
) -> int:
    """Insert spec/postman rows, skipping any that already exist."""
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
            select(func.count()).select_from(endpoint_table).where(
                endpoint_table.c.api_id == api_id
            )
        ).scalar_one()
        connection.execute(stmt)
        after_count = connection.execute(
            select(func.count()).select_from(endpoint_table).where(
                endpoint_table.c.api_id == api_id
            )
        ).scalar_one()
    return after_count - before_count


def _insert_traffic(engine: Engine, api_id: int, endpoints: list[DiscoveredEndpoint]) -> int:
    """Process traffic-observed endpoints.

    For each observed (method, path):
    - If a row already exists for (api_id, path, method): update seen_in_traffic=True.
    - If no row exists: insert a new row with source='traffic'.

    Returns the number of new rows inserted.
    """
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
    # ON CONFLICT: if (api_id, path, method) already exists, just set seen_in_traffic=True.
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
            select(func.count()).select_from(endpoint_table).where(
                endpoint_table.c.api_id == api_id
            )
        ).scalar_one()
        connection.execute(stmt)
        after_count = connection.execute(
            select(func.count()).select_from(endpoint_table).where(
                endpoint_table.c.api_id == api_id
            )
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
