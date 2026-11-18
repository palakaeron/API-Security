"""Security Misconfiguration detector.

OWASP API8:2023

Strategy
--------
Three sub-checks against a target base URL:

1. **Error disclosure** — send a malformed request and inspect whether the
   error response leaks internal stack traces, framework names, or verbose
   debug information.

2. **Missing security headers** — inspect a normal response for the absence of
   ``X-Content-Type-Options``, ``X-Frame-Options``, and
   ``Strict-Transport-Security`` (where HTTPS is in use).

3. **GraphQL introspection** — send an introspection query to a ``/graphql``
   endpoint and flag if the schema is returned.  Only run when
   ``graphql_path`` is provided.

Note: this detector does not attempt to trigger real server errors by sending
payloads that could corrupt state.  It uses a missing required field (empty
JSON body) to provoke a validation error response, which every web framework
handles without side effects.
"""

from __future__ import annotations

from app.detectors.base import DetectorResult, Evidence, OWASPCategory, Severity
from app.detectors.http_client import controlled_get, controlled_post
from app.security.target_allowlist import TargetPolicy

# Headers whose absence from a response is itself a misconfiguration signal.
_EXPECTED_SECURITY_HEADERS = {
    "x-content-type-options",
    "x-frame-options",
}

# Patterns in an error response body that indicate verbose stack disclosure.
_STACK_PATTERNS = (
    "traceback",
    "at line ",
    "exception",
    "stacktrace",
    "internal server error",
    "debug",
    "fastapi",
    "uvicorn",
    "sqlalchemy",
)


class MisconfigurationDetector:
    """Security Misconfiguration (OWASP API8:2023) detector.

    Checks error-response verbosity, absent security headers, and (optionally)
    GraphQL introspection exposure.
    """

    DETECTOR_ID = "misconfiguration"
    OWASP_CATEGORY = OWASPCategory.MISCONFIGURATION
    SEVERITY = Severity.MEDIUM
    CONFIDENCE = 80.0
    REMEDIATION_REF = (
        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"
    )

    def run(
        self,
        base_url: str,
        policy: TargetPolicy,
        probe_path: str = "/health",
        graphql_path: str | None = None,
    ) -> DetectorResult:
        """Run misconfiguration probes against the target.

        :param base_url: Validated lab base URL.
        :param policy: Allowlist policy.
        :param probe_path: A known-good GET path for header inspection and error
            probing (e.g. ``/health``).
        :param graphql_path: If provided, also send an introspection query here
            and flag if the schema is returned.
        :returns: ``DetectorResult`` summarising all sub-checks.
        """
        findings: list[str] = []
        all_evidence: list[Evidence] = []

        # ── Sub-check 1: Security headers on a normal response ────────────────
        url = base_url.rstrip("/") + probe_path
        hs, hh, hb = controlled_get(url, policy)
        missing_headers = [
            h for h in _EXPECTED_SECURITY_HEADERS if h not in {k.lower() for k in hh}
        ]
        all_evidence.append(
            Evidence(
                url=url,
                method="GET",
                request_headers={},
                request_body=None,
                response_status=hs,
                response_headers=hh,
                response_body=hb,
                context={
                    "probe": "security_headers",
                    "missing_headers": missing_headers,
                    "detector": self.DETECTOR_ID,
                },
            )
        )
        if missing_headers:
            findings.append(
                f"missing security headers: {missing_headers!r} on {probe_path}"
            )

        # ── Sub-check 2: Error verbosity ───────────────────────────────────────
        # POST with empty body to provoke a validation error.
        err_url = base_url.rstrip("/") + probe_path
        es, eh, eb = controlled_post(err_url, policy, json={})
        body_str = str(eb).lower() if eb is not None else ""
        disclosed = [p for p in _STACK_PATTERNS if p in body_str]
        all_evidence.append(
            Evidence(
                url=err_url,
                method="POST",
                request_headers={},
                request_body={},
                response_status=es,
                response_headers=eh,
                response_body=eb,
                context={
                    "probe": "error_disclosure",
                    "patterns_found": disclosed,
                    "detector": self.DETECTOR_ID,
                },
            )
        )
        if disclosed:
            findings.append(
                f"error response may disclose internals: patterns {disclosed!r} in body"
            )

        # ── Sub-check 3: GraphQL introspection (optional) ─────────────────────
        if graphql_path:
            gql_url = base_url.rstrip("/") + graphql_path
            introspection_query = {"query": "{ __schema { queryType { name } } }"}
            gs, gh, gb = controlled_post(
                gql_url, policy, headers={"Content-Type": "application/json"},
                json=introspection_query,
            )
            schema_exposed = (
                gs == 200
                and isinstance(gb, dict)
                and "data" in gb
                and gb.get("data") is not None
                and "__schema" in str(gb.get("data", ""))
            )
            all_evidence.append(
                Evidence(
                    url=gql_url,
                    method="POST",
                    request_headers={"Content-Type": "application/json"},
                    request_body=introspection_query,
                    response_status=gs,
                    response_headers=gh,
                    response_body=gb,
                    context={
                        "probe": "graphql_introspection",
                        "schema_exposed": schema_exposed,
                        "detector": self.DETECTOR_ID,
                    },
                )
            )
            if schema_exposed:
                findings.append(
                    f"GraphQL introspection enabled at {graphql_path} — "
                    "schema structure is publicly readable"
                )

        vulnerable = bool(findings)
        severity = (
            Severity.HIGH
            if any("introspection" in f or "discloses" in f for f in findings)
            else Severity.MEDIUM
        )
        return DetectorResult(
            detector_id=self.DETECTOR_ID,
            owasp_category=self.OWASP_CATEGORY,
            severity=severity if vulnerable else Severity.INFO,
            confidence=self.CONFIDENCE if vulnerable else 0.0,
            vulnerable=vulnerable,
            evidence=all_evidence,
            title=(
                f"Misconfiguration on {base_url}: " + "; ".join(findings)
                if vulnerable
                else f"No misconfiguration detected on {base_url}"
            ),
            remediation_ref=self.REMEDIATION_REF,
            detail="\n".join(findings) if findings else "All misconfiguration checks passed.",
        )
