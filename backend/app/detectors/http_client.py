"""Allowlist-enforcing HTTP client for the detection engine.

EVERY outbound request made by a detector MUST go through ``controlled_get``
or ``controlled_post``.  These functions call ``validate_controlled_target``
before opening any connection, so a detector cannot accidentally (or by
injection) reach a target outside the controlled lab.

Response bodies and headers are sanitised before being returned so that raw
JWT / token values never flow into Evidence objects.

The client uses ``httpx`` with a short timeout; connection errors are caught
and re-raised as ``DetectorHTTPError`` so detectors can handle them cleanly
without leaking stack traces to callers.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.detectors.sanitiser import sanitise_body, sanitise_headers
from app.security.target_allowlist import TargetPolicy, validate_controlled_target

DEFAULT_TIMEOUT = 10.0  # seconds


class DetectorHTTPError(RuntimeError):
    """Raised when a controlled HTTP request fails at the transport level."""


def _build_evidence_response(resp: httpx.Response) -> tuple[int, dict[str, str], Any]:
    """Extract status, sanitised headers, and sanitised body from a response."""
    headers = sanitise_headers(dict(resp.headers))
    try:
        body = sanitise_body(resp.json())
    except Exception:  # noqa: BLE001
        body = sanitise_body(resp.text[:2000])
    return resp.status_code, headers, body


def _build_raw_response(resp: httpx.Response) -> tuple[int, dict[str, str], Any]:
    """Extract status, sanitised headers, and RAW (unsanitised) body from a response.

    Use only when the caller immediately consumes and discards the sensitive
    value (e.g. JWT analyzer extracting a token for cryptographic analysis).
    The body must never be stored in Evidence objects.
    """
    headers = sanitise_headers(dict(resp.headers))
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = resp.text[:2000]
    return resp.status_code, headers, body


def controlled_request(
    method: str,
    url: str,
    policy: TargetPolicy,
    *,
    headers: dict[str, str] | None = None,
    json: Any = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, dict[str, str], Any]:
    """Make a controlled HTTP request, enforcing the allowlist check first.

    Returns ``(status_code, sanitised_headers, sanitised_body)``.

    Raises:
        TargetNotAllowed: if ``url`` is not on the controlled lab allowlist.
        DetectorHTTPError: if the network request itself fails.
    """
    validated_url = validate_controlled_target(url, policy)
    try:
        resp = httpx.request(
            method=method.upper(),
            url=validated_url,
            headers=headers or {},
            json=json,
            follow_redirects=False,
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise DetectorHTTPError(f"HTTP request to {url!r} failed: {exc}") from exc
    return _build_evidence_response(resp)


def controlled_get(
    url: str,
    policy: TargetPolicy,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, dict[str, str], Any]:
    """GET wrapper — see ``controlled_request``."""
    return controlled_request("GET", url, policy, headers=headers, timeout=timeout)


def controlled_post(
    url: str,
    policy: TargetPolicy,
    *,
    headers: dict[str, str] | None = None,
    json: Any = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, dict[str, str], Any]:
    """POST wrapper — see ``controlled_request``."""
    return controlled_request("POST", url, policy, headers=headers, json=json, timeout=timeout)


def controlled_post_raw(
    url: str,
    policy: TargetPolicy,
    *,
    headers: dict[str, str] | None = None,
    json: Any = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, dict[str, str], Any]:
    """POST wrapper returning the unsanitised response body.

    Use ONLY when the caller needs to extract a token or credential for
    cryptographic analysis (e.g. JWT analyzer) and will NOT store the raw
    body in Evidence objects.  The body must be consumed and discarded
    immediately — never persisted.
    """
    validated_url = validate_controlled_target(url, policy)
    try:
        resp = httpx.request(
            method="POST",
            url=validated_url,
            headers=headers or {},
            json=json,
            follow_redirects=False,
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise DetectorHTTPError(f"HTTP request to {url!r} failed: {exc}") from exc
    return _build_raw_response(resp)


def controlled_patch(
    url: str,
    policy: TargetPolicy,
    *,
    headers: dict[str, str] | None = None,
    json: Any = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, dict[str, str], Any]:
    """PATCH wrapper — see ``controlled_request``."""
    return controlled_request("PATCH", url, policy, headers=headers, json=json, timeout=timeout)
