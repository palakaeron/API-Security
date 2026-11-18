"""Evidence sanitiser — masks sensitive values before they are stored or logged.

Patterns masked:
- Authorization / bearer token header values
- JWT strings (three base64url segments separated by dots)
- Values that look like card numbers (13–19 contiguous digits)
- Anything in a field whose key contains "secret", "password", "token",
  "key", "credential", or "pin"

This module is deliberately conservative: it would rather mask a non-secret
than leak a real one.  The mask value is the literal string ``[REDACTED]``.
"""

from __future__ import annotations

import re
from typing import Any

# JWT: three base64url segments (header.payload.signature)
_JWT_RE = re.compile(
    r"ey[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"
)
# Bearer token in Authorization header value
_BEARER_RE = re.compile(r"(?i)(Bearer\s+)\S+")
# Card-like: 13–19 consecutive digits (with optional spaces/dashes between groups)
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\d\b")

# Field-name keywords whose values are always masked regardless of content
_SENSITIVE_KEYS = frozenset(
    {"secret", "password", "passwd", "token", "key", "credential", "pin", "auth", "apikey"}
)

REDACTED = "[REDACTED]"


def _mask_string(value: str) -> str:
    value = _BEARER_RE.sub(r"\1" + REDACTED, value)
    value = _JWT_RE.sub(REDACTED, value)
    value = _CARD_RE.sub(REDACTED, value)
    return value


def _key_is_sensitive(key: str) -> bool:
    lower = key.lower()
    return any(s in lower for s in _SENSITIVE_KEYS)


def sanitise_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``headers`` with sensitive values masked."""
    result: dict[str, str] = {}
    for k, v in headers.items():
        if _key_is_sensitive(k):
            result[k] = REDACTED
        else:
            result[k] = _mask_string(str(v))
    return result


def sanitise_body(body: Any) -> Any:
    """Recursively sanitise a JSON-serialisable body (dict, list, str, or scalar)."""
    if isinstance(body, dict):
        return {
            k: REDACTED if _key_is_sensitive(k) else sanitise_body(v)
            for k, v in body.items()
        }
    if isinstance(body, list):
        return [sanitise_body(item) for item in body]
    if isinstance(body, str):
        return _mask_string(body)
    return body
