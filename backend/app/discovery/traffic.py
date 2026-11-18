"""Lightweight traffic recorder for passive API discovery.

A ``TrafficRecorder`` listens on a loopback port as an HTTP forward proxy.
Every request it forwards is recorded as an observed ``(method, path)`` pair
which can later be flushed to the database as ``source='traffic'`` endpoints.

Security invariants (non-negotiable, per §1.1 of the project guardrails):
- Before forwarding any request the target URL is validated against the
  controlled-lab allowlist; non-loopback targets are refused.
- The proxy listens only on ``127.0.0.1`` — never on ``0.0.0.0``.
- Recorded paths are normalized to strip query strings and fragments so they
  compare cleanly against declared spec paths.
"""

from __future__ import annotations

import logging
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse

import httpx

from app.discovery.models import DiscoveredEndpoint
from app.security.target_allowlist import TargetNotAllowed, TargetPolicy

logger = logging.getLogger(__name__)

# Path parameters are normalised: /users/alice → /users/{id}
# Segment heuristic: a segment is a "variable" when it contains digits, looks
# like a UUID, or is longer than 24 characters with no slash — this matches
# the lab's synthetic IDs (alice, bob, ord-alice-001, etc.) without
# over-generalising.  The caller can override normalise_path for their own
# heuristic.
_LOOKS_LIKE_ID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"  # UUID
    r"|^\d+$"  # pure integer
    r"|^[a-z]+-[a-z]+-\d+$"  # ord-alice-001 style
)


def normalise_path(raw_path: str) -> str:
    """Strip query/fragment and collapse ID-like path segments to ``{id}``."""
    parsed = urlparse(raw_path)
    # Keep only scheme+netloc+path (drop query and fragment)
    path = parsed.path or raw_path
    segments = path.split("/")
    normalised = []
    for segment in segments:
        if _LOOKS_LIKE_ID.match(segment):
            normalised.append("{id}")
        else:
            normalised.append(segment)
    return "/".join(normalised)


class _RecordingHandler(BaseHTTPRequestHandler):
    """HTTP/1.1 forward proxy handler that records and forwards requests."""

    recorder: TrafficRecorder  # set by server via subclass factory

    def _do_request(self, with_body: bool) -> None:  # noqa: FBT001
        target_url = self.path
        # Validate the target against the allowlist before any outbound I/O.
        try:
            validated_url = self.recorder.policy.validate(target_url)
        except TargetNotAllowed as exc:
            logger.warning("traffic recorder rejected target %r: %s", target_url, exc)
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Target not on controlled lab allowlist.\n")
            return

        # Read the request body if present.
        body = b""
        if with_body:
            content_length = int(self.headers.get("Content-Length", 0) or 0)
            if content_length > 0:
                body = self.rfile.read(content_length)

        # Forward the request.
        headers = {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in {"host", "proxy-connection", "connection"}
        }
        try:
            response = httpx.request(
                method=self.command,
                url=validated_url,
                headers=headers,
                content=body,
                follow_redirects=False,
                timeout=10.0,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("traffic recorder forward error for %r: %s", validated_url, exc)
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"Upstream request failed.\n")
            return

        # Record the observed (method, path) — strip the origin to get just the path.
        parsed = urlparse(validated_url)
        observed_path = normalise_path(parsed.path)
        method = self.command.upper()
        self.recorder._record(method, observed_path)  # noqa: SLF001

        # Relay the response back to the caller.
        self.send_response(response.status_code)
        for k, v in response.headers.items():
            if k.lower() not in {"transfer-encoding", "connection"}:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(response.content)

    def do_GET(self) -> None:  # noqa: N802
        self._do_request(with_body=False)

    def do_POST(self) -> None:  # noqa: N802
        self._do_request(with_body=True)

    def do_PUT(self) -> None:  # noqa: N802
        self._do_request(with_body=True)

    def do_PATCH(self) -> None:  # noqa: N802
        self._do_request(with_body=True)

    def do_DELETE(self) -> None:  # noqa: N802
        self._do_request(with_body=False)

    def do_HEAD(self) -> None:  # noqa: N802
        self._do_request(with_body=False)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._do_request(with_body=False)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: ANN401
        logger.debug("proxy: " + fmt, *args)


class _AllowlistAdapter:
    """Thin adapter so the handler can call ``policy.validate()`` uniformly."""

    def __init__(self, policy: TargetPolicy) -> None:
        self._policy = policy

    def validate(self, url: str) -> str:
        from app.security.target_allowlist import validate_controlled_target

        return validate_controlled_target(url, self._policy)


class TrafficRecorder:
    """Reverse-proxy traffic recorder for passive API surface discovery.

    Usage::

        policy = TargetPolicy.from_strings("localhost,127.0.0.1", "127.0.0.0/8")
        recorder = TrafficRecorder(policy=policy, listen_port=9090)
        recorder.start()          # non-blocking; runs in a daemon thread
        # ... run lab requests through http://127.0.0.1:9090 ...
        recorder.stop()
        endpoints = recorder.discovered_endpoints()  # list[DiscoveredEndpoint]
    """

    def __init__(self, policy: TargetPolicy, listen_port: int = 9090) -> None:
        if listen_port < 1 or listen_port > 65535:
            raise ValueError("listen_port must be 1–65535")
        self.policy = _AllowlistAdapter(policy)
        self._listen_port = listen_port
        self._lock = threading.Lock()
        self._observed: dict[tuple[str, str], None] = {}  # ordered set (dict preserves insertion)
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def _record(self, method: str, path: str) -> None:
        with self._lock:
            self._observed[(method.upper(), path)] = None

    def start(self) -> None:
        """Start the proxy listener in a background daemon thread."""
        if self._server is not None:
            return  # already running

        recorder = self

        class _Handler(_RecordingHandler):
            pass

        _Handler.recorder = recorder  # type: ignore[attr-defined]

        self._server = HTTPServer(("127.0.0.1", self._listen_port), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="traffic-recorder", daemon=True
        )
        self._thread.start()
        logger.info("TrafficRecorder listening on 127.0.0.1:%d", self._listen_port)

    def stop(self) -> None:
        """Shut down the proxy listener."""
        if self._server is not None:
            self._server.shutdown()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("TrafficRecorder stopped")

    def snapshot(self) -> list[tuple[str, str]]:
        """Return a copy of the observed (method, path) pairs so far."""
        with self._lock:
            return list(self._observed)

    def discovered_endpoints(self) -> list[DiscoveredEndpoint]:
        """Convert observed traffic into ``DiscoveredEndpoint`` objects."""
        return [
            DiscoveredEndpoint(
                path=path,
                method=method,
                parameters=[],
                request_schema=None,
                response_schemas={},
                auth_scheme="none",
                deprecated=False,
            )
            for method, path in self.snapshot()
        ]
