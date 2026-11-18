"""Non-executing parsers for OpenAPI 3.x and Postman Collection v2.1."""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

from app.discovery.models import DiscoveredEndpoint, ImportValidationError

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

# Normalise Postman {{variable}} path segments to OpenAPI {variable} form so
# that paths from both formats compare as equal.
_POSTMAN_VAR = re.compile(r"^\{\{(.+?)\}\}$")


def _load_document(content: str | bytes) -> dict[str, Any]:
    try:
        value = (
            json.loads(content)
            if isinstance(content, str) and content.lstrip().startswith(("{", "["))
            else yaml.safe_load(content)
        )
    except (json.JSONDecodeError, yaml.YAMLError) as error:
        raise ImportValidationError("document is not valid JSON or YAML") from error
    if not isinstance(value, dict):
        raise ImportValidationError("document root must be an object")
    return value


def _auth_from_security(security: Any, schemes: dict[str, Any]) -> str:
    if not security:
        return "none"
    if not isinstance(security, list) or not isinstance(security[0], dict):
        raise ImportValidationError("security declaration must be an array of objects")
    name = next(iter(security[0]), None)
    scheme = schemes.get(name, {})
    if scheme.get("type") == "apiKey":
        return "api_key"
    if scheme.get("type") == "http" and scheme.get("scheme") == "bearer":
        return "bearer_jwt"
    if scheme.get("type") == "oauth2":
        return "oauth2"
    return "none"


def parse_openapi(content: str | bytes) -> list[DiscoveredEndpoint]:
    document = _load_document(content)
    if not str(document.get("openapi", "")).startswith("3.") or not isinstance(
        document.get("paths"), dict
    ):
        raise ImportValidationError("OpenAPI 3.x document with paths is required")
    schemes = document.get("components", {}).get("securitySchemes", {})
    endpoints = []
    for path, path_item in document["paths"].items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
            raise ImportValidationError("each OpenAPI path must be an object beginning with '/'")
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                raise ImportValidationError("each OpenAPI operation must be an object")
            parameters = list(path_item.get("parameters", [])) + list(
                operation.get("parameters", [])
            )
            request = (
                operation.get("requestBody", {}).get("content", {})
                if isinstance(operation.get("requestBody", {}), dict)
                else {}
            )
            request_schema = next(
                (item.get("schema") for item in request.values() if isinstance(item, dict)), None
            )
            responses = operation.get("responses", {})
            if not isinstance(responses, dict):
                raise ImportValidationError("OpenAPI responses must be an object")
            response_schemas = {
                str(code): value.get("content", {})
                for code, value in responses.items()
                if isinstance(value, dict)
            }
            endpoints.append(
                DiscoveredEndpoint(
                    path,
                    method.upper(),
                    parameters,
                    request_schema,
                    response_schemas,
                    _auth_from_security(
                        operation.get("security", document.get("security")), schemes
                    ),
                    bool(operation.get("deprecated")),
                )
            )
    return endpoints


def _normalise_postman_path(segments: list[str]) -> str:
    """Join URL path segments and normalise ``{{var}}`` to ``{var}``.

    Postman uses double-brace syntax for path variables while OpenAPI uses
    single-brace.  Normalising at parse time means paths from both formats
    can be compared directly.
    """
    normalised = [
        "{" + m.group(1) + "}" if (m := _POSTMAN_VAR.match(seg)) else seg
        for seg in segments
    ]
    return "/" + "/".join(normalised)


def parse_postman(content: str | bytes) -> list[DiscoveredEndpoint]:
    document = _load_document(content)
    info = document.get("info", {})
    if not isinstance(info, dict) or "/v2.1" not in str(info.get("schema", "")):
        raise ImportValidationError("Postman Collection v2.1 document required")
    endpoints: list[DiscoveredEndpoint] = []

    def visit(items: Any) -> None:
        if not isinstance(items, list):
            raise ImportValidationError("Postman item must be an array")
        for item in items:
            if not isinstance(item, dict):
                raise ImportValidationError("Postman item must be an object")
            if "item" in item:
                visit(item["item"])
                continue
            request = item.get("request", {})
            if not isinstance(request, dict):
                raise ImportValidationError("Postman request must be an object")
            method = str(request.get("method", "")).upper()
            raw_url = request.get("url", {})
            path = (
                _normalise_postman_path(raw_url.get("path", []))
                if isinstance(raw_url, dict)
                else ""
            )
            if method not in {m.upper() for m in HTTP_METHODS} or not path or path == "/":
                raise ImportValidationError("Postman request needs method and URL path")
            headers = request.get("header", [])
            auth = request.get("auth", {})
            auth_type = {"bearer": "bearer_jwt", "apikey": "api_key", "oauth2": "oauth2"}.get(
                auth.get("type") if isinstance(auth, dict) else "", "none"
            )
            endpoints.append(
                DiscoveredEndpoint(
                    path,
                    method,
                    headers if isinstance(headers, list) else [],
                    request.get("body"),
                    {},
                    auth_type,
                )
            )

    visit(document.get("item"))
    return endpoints
