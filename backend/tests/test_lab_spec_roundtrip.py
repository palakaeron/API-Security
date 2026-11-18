from pathlib import Path

from app.discovery.parsers import parse_openapi

ROOT = Path(__file__).parents[2]
EXPECTED = {
    "auth": {("/vuln/auth/token", "POST", "none"), ("/secure/auth/token", "POST", "none")},
    "users": {
        ("/vuln/users/{user_id}", "GET", "bearer_jwt"),
        ("/secure/users/{user_id}", "GET", "bearer_jwt"),
        ("/vuln/profiles/{user_id}", "GET", "bearer_jwt"),
        ("/vuln/profiles/{user_id}", "PATCH", "bearer_jwt"),
        ("/secure/profiles/{user_id}", "GET", "bearer_jwt"),
        ("/secure/profiles/{user_id}", "PATCH", "bearer_jwt"),
    },
    "admin": {
        ("/vuln/admin/audit", "GET", "bearer_jwt"),
        ("/secure/admin/audit", "GET", "bearer_jwt"),
    },
    "payments": {
        ("/vuln/payments/{user_id}", "GET", "bearer_jwt"),
        ("/secure/payments/{user_id}", "GET", "bearer_jwt"),
    },
    "orders": {
        ("/vuln/orders/{order_id}", "GET", "bearer_jwt"),
        ("/secure/orders/{order_id}", "GET", "bearer_jwt"),
    },
    "inventory": {("/v1/users/{user_id}", "GET", "none")},
    "graphql": {("/vuln/graphql", "POST", "none"), ("/secure/graphql", "POST", "none")},
}


def test_all_seven_lab_specs_round_trip_exactly() -> None:
    for service, expected in EXPECTED.items():
        content = (ROOT / "lab" / "openapi" / "services" / f"{service}.yaml").read_text(
            encoding="utf-8"
        )
        actual = {(item.path, item.method, item.auth_scheme) for item in parse_openapi(content)}
        assert actual == expected, service
