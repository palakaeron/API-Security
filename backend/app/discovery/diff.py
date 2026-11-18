"""Shadow and zombie endpoint diffing.

Definitions used in this project:

- **Shadow endpoint**: an ``(api_id, method, path)`` observed in captured
  traffic (``source='traffic'``) that does NOT appear in the declared spec
  (``source`` IN ``{'spec', 'postman'}``).  These are undocumented endpoints
  that could indicate unintended exposure.

- **Zombie endpoint**: an endpoint that IS declared in the spec with
  ``deprecated=True`` AND has also appeared in captured traffic
  (``seen_in_traffic=True``).  The endpoint is still actively reachable despite
  being marked as deprecated, indicating Improper Inventory Management.

Both results carry the structured fields needed to create findings later (M4).
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine, select

from app.discovery.persistence import endpoint_table


@dataclass(frozen=True)
class EndpointRef:
    """A normalised reference to an endpoint suitable for diffing."""

    path: str
    method: str
    deprecated: bool = False


@dataclass
class DiffResult:
    """Structured diff output for a single api_id."""

    api_id: int
    shadow: list[EndpointRef]
    """Endpoints seen in traffic but absent from the declared spec."""
    zombie: list[EndpointRef]
    """Declared-deprecated endpoints that have also appeared in traffic."""

    @property
    def has_findings(self) -> bool:
        return bool(self.shadow or self.zombie)


def diff_endpoints(engine: Engine, api_id: int) -> DiffResult:
    """Compute the shadow/zombie diff for ``api_id``.

    Queries the ``endpoints`` table and produces shadow/zombie lists using
    the ``source`` and ``seen_in_traffic`` columns.  No outbound network
    calls are made — this is a pure in-database comparison.

    :param engine: SQLAlchemy engine connected to the platform database.
    :param api_id: The API row whose endpoints should be compared.
    :returns: A :class:`DiffResult` with shadow and zombie lists.
    """
    t = endpoint_table

    with engine.connect() as conn:
        all_rows = conn.execute(
            select(t.c.path, t.c.method, t.c.source, t.c.deprecated, t.c.seen_in_traffic).where(
                t.c.api_id == api_id
            )
        ).fetchall()

    # Shadow: rows whose source is 'traffic' only (no matching declared row).
    # These are rows that were inserted as source='traffic' because they had no
    # existing declared (spec/postman) counterpart.
    shadow: list[EndpointRef] = sorted(
        [
            EndpointRef(path=str(row.path), method=str(row.method).upper())
            for row in all_rows
            if row.source == "traffic"
        ],
        key=lambda e: (e.method, e.path),
    )

    # Zombie: declared rows (spec/postman) that are deprecated AND have been
    # seen in traffic (seen_in_traffic=True).
    zombie: list[EndpointRef] = sorted(
        [
            EndpointRef(path=str(row.path), method=str(row.method).upper(), deprecated=True)
            for row in all_rows
            if row.source in {"spec", "postman"}
            and bool(row.deprecated)
            and bool(row.seen_in_traffic)
        ],
        key=lambda e: (e.method, e.path),
    )

    return DiffResult(api_id=api_id, shadow=shadow, zombie=zombie)
