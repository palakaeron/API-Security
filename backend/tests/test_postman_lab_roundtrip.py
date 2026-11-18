"""Postman ↔ OpenAPI round-trip parity tests for lab services.

For each lab service that has both a Postman collection and an OpenAPI spec,
this module verifies that:

1. ``parse_postman`` and ``parse_openapi`` produce the same ``(path, method)``
   set — i.e., no endpoint is present in one format but missing in the other.
2. The auth scheme extracted from the Postman collection matches the auth
   scheme extracted from the OpenAPI spec for every operation.

This is the Stage-1 M3 acceptance criterion: *both import paths produce a
consistent inventory for the same service.*

Services covered:
- **auth** (port 8101): 2 endpoints, both unauthenticated POST
- **users** (port 8102): 6 endpoints (users × 2 + profiles GET × 2 + profiles PATCH × 2),
  all bearer_jwt

The Postman collections live at ``lab/postman/``;
the OpenAPI specs live at ``lab/openapi/services/``.
"""

from __future__ import annotations

from pathlib import Path

from app.discovery.parsers import parse_openapi, parse_postman

LAB_ROOT = Path(__file__).parents[2] / "lab"
POSTMAN_DIR = LAB_ROOT / "postman"
OPENAPI_DIR = LAB_ROOT / "openapi" / "services"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _postman_endpoint_set(collection_path: Path) -> set[tuple[str, str, str]]:
    """Return {(path, method, auth_scheme)} from a Postman collection file."""
    content = collection_path.read_text(encoding="utf-8")
    return {(ep.path, ep.method, ep.auth_scheme) for ep in parse_postman(content)}


def _openapi_endpoint_set(spec_path: Path) -> set[tuple[str, str, str]]:
    """Return {(path, method, auth_scheme)} from an OpenAPI spec file."""
    content = spec_path.read_text(encoding="utf-8")
    return {(ep.path, ep.method, ep.auth_scheme) for ep in parse_openapi(content)}


# ---------------------------------------------------------------------------
# Auth service — 2 endpoints, both unauthenticated POST
# ---------------------------------------------------------------------------


class TestAuthServiceRoundTrip:
    """auth-collection.json  ↔  services/auth.yaml"""

    postman = POSTMAN_DIR / "auth-collection.json"
    openapi = OPENAPI_DIR / "auth.yaml"

    EXPECTED: set[tuple[str, str, str]] = {
        ("/vuln/auth/token", "POST", "none"),
        ("/secure/auth/token", "POST", "none"),
    }

    def test_postman_collection_parses_to_expected_endpoint_set(self) -> None:
        actual = _postman_endpoint_set(self.postman)
        assert actual == self.EXPECTED, (
            f"Postman auth collection mismatch.\n"
            f"  Extra:   {actual - self.EXPECTED}\n"
            f"  Missing: {self.EXPECTED - actual}"
        )

    def test_openapi_spec_parses_to_expected_endpoint_set(self) -> None:
        actual = _openapi_endpoint_set(self.openapi)
        assert actual == self.EXPECTED, (
            f"OpenAPI auth spec mismatch.\n"
            f"  Extra:   {actual - self.EXPECTED}\n"
            f"  Missing: {self.EXPECTED - actual}"
        )

    def test_postman_and_openapi_produce_identical_path_method_sets(self) -> None:
        """Core parity: both import paths agree on every (path, method, auth_scheme)."""
        postman_set = _postman_endpoint_set(self.postman)
        openapi_set = _openapi_endpoint_set(self.openapi)
        assert postman_set == openapi_set, (
            f"Auth service import parity failure.\n"
            f"  In Postman only:  {postman_set - openapi_set}\n"
            f"  In OpenAPI only:  {openapi_set - postman_set}"
        )


# ---------------------------------------------------------------------------
# Users service — 6 endpoints, all bearer_jwt
# ---------------------------------------------------------------------------


class TestUsersServiceRoundTrip:
    """users-collection.json  ↔  services/users.yaml"""

    postman = POSTMAN_DIR / "users-collection.json"
    openapi = OPENAPI_DIR / "users.yaml"

    EXPECTED: set[tuple[str, str, str]] = {
        ("/vuln/users/{user_id}", "GET", "bearer_jwt"),
        ("/secure/users/{user_id}", "GET", "bearer_jwt"),
        ("/vuln/profiles/{user_id}", "GET", "bearer_jwt"),
        ("/vuln/profiles/{user_id}", "PATCH", "bearer_jwt"),
        ("/secure/profiles/{user_id}", "GET", "bearer_jwt"),
        ("/secure/profiles/{user_id}", "PATCH", "bearer_jwt"),
    }

    def test_postman_collection_parses_to_expected_endpoint_set(self) -> None:
        actual = _postman_endpoint_set(self.postman)
        assert actual == self.EXPECTED, (
            f"Postman users collection mismatch.\n"
            f"  Extra:   {actual - self.EXPECTED}\n"
            f"  Missing: {self.EXPECTED - actual}"
        )

    def test_openapi_spec_parses_to_expected_endpoint_set(self) -> None:
        actual = _openapi_endpoint_set(self.openapi)
        assert actual == self.EXPECTED, (
            f"OpenAPI users spec mismatch.\n"
            f"  Extra:   {actual - self.EXPECTED}\n"
            f"  Missing: {self.EXPECTED - actual}"
        )

    def test_postman_and_openapi_produce_identical_path_method_sets(self) -> None:
        """Core parity: both import paths agree on every (path, method, auth_scheme)."""
        postman_set = _postman_endpoint_set(self.postman)
        openapi_set = _openapi_endpoint_set(self.openapi)
        assert postman_set == openapi_set, (
            f"Users service import parity failure.\n"
            f"  In Postman only:  {postman_set - openapi_set}\n"
            f"  In OpenAPI only:  {openapi_set - postman_set}"
        )

    def test_postman_path_variable_normalisation(self) -> None:
        """Postman {{user_id}} segments must be normalised to {user_id} at parse time."""
        postman_set = _postman_endpoint_set(self.postman)
        # Every path containing a variable placeholder must use single-brace form.
        bad = [path for path, _, _ in postman_set if "{{" in path or "}}" in path]
        assert not bad, (
            f"Found un-normalised Postman variable syntax in paths: {bad}"
        )

    def test_postman_nested_folder_structure_is_flattened(self) -> None:
        """Items inside Postman folders (Users, Profiles) must all be collected."""
        postman_set = _postman_endpoint_set(self.postman)
        # If folder recursion is broken, we'd get fewer than 6 endpoints.
        assert len(postman_set) == 6, (
            f"Expected 6 endpoints from nested collection; got {len(postman_set)}: {postman_set}"
        )
