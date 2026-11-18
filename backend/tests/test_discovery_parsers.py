import json

import pytest
from app.discovery.models import ImportValidationError
from app.discovery.parsers import parse_openapi, parse_postman


def test_openapi_normalizes_path_method_auth_and_deprecation() -> None:
    spec = {
        "openapi": "3.0.3",
        "components": {"securitySchemes": {"jwt": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/orders/{id}": {
                "get": {
                    "security": [{"jwt": []}],
                    "deprecated": True,
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    endpoint = parse_openapi(json.dumps(spec))[0]
    assert (endpoint.path, endpoint.method, endpoint.auth_scheme, endpoint.deprecated) == (
        "/orders/{id}",
        "GET",
        "bearer_jwt",
        True,
    )


def test_postman_normalizes_without_running_scripts() -> None:
    collection = {
        "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "event": [{"listen": "prerequest", "script": {"exec": ["throw new Error()"]}}],
        "item": [
            {
                "request": {
                    "method": "GET",
                    "url": {"path": ["users", "alice"]},
                    "auth": {"type": "bearer"},
                }
            }
        ],
    }
    endpoint = parse_postman(json.dumps(collection))[0]
    assert (endpoint.path, endpoint.method, endpoint.auth_scheme) == (
        "/users/alice",
        "GET",
        "bearer_jwt",
    )


def test_malformed_documents_are_rejected() -> None:
    with pytest.raises(ImportValidationError):
        parse_openapi("openapi: 2.0\npaths: {}")
