from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DiscoveredEndpoint:
    path: str
    method: str
    parameters: list[dict[str, Any]]
    request_schema: dict[str, Any] | None
    response_schemas: dict[str, Any]
    auth_scheme: str
    deprecated: bool = False


class ImportValidationError(ValueError):
    """A supplied inventory document is malformed or unsupported."""
