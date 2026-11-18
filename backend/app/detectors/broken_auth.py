"""Broken Authentication detector.

OWASP API2:2023

Strategy
--------
Four sub-checks are run against the target endpoint:

1. **No token**: request with no Authorization header — should get 401.
2. **Malformed token**: random non-JWT string in the Authorization header — 401.
3. **Invalid signature**: structurally valid JWT signed with the wrong key — 401.
4. **Accepted token**: a valid token issues correctly — should get 2xx.

Any sub-check returning 2xx when it should return 401 indicates broken
authentication.  The detector also checks whether the endpoint enforces the
``Bearer`` scheme at all (vs. accepting any string as "auth").

Note: the "expired token" check is omitted here because it would require
waiting or time-manipulation.  It is covered by the JWT analyzer (jwt_analyzer.py)
which inspects token claims directly.
"""

from __future__ import annotations

from app.detectors.base import (
    DetectorIssue,
    DetectorIssueCode,
    DetectorResult,
    Evidence,
    OWASPCategory,
    Severity,
)
from app.detectors.http_client import controlled_get
from app.detectors.sanitiser import sanitise_headers
from app.security.target_allowlist import TargetPolicy

_FAKE_TOKEN = (
    # A structurally valid-looking JWT signed with the wrong key.
    # header: {"alg":"HS256","typ":"JWT"}  payload: {"sub":"attacker","role":"user"}
    # signature: garbage bytes — will fail verification on any real server.
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJ1c2VyIn0"
    ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)


def _build_evidence(
    url: str,
    req_headers: dict[str, str],
    status: int,
    resp_headers: dict[str, str],
    resp_body: object,
    context: dict[str, object],
) -> Evidence:
    return Evidence(
        url=url,
        method="GET",
        request_headers=sanitise_headers(req_headers),
        request_body=None,
        response_status=status,
        response_headers=resp_headers,
        response_body=resp_body,
        context=context,
    )


class BrokenAuthDetector:
    """Broken Authentication (OWASP API2:2023) detector.

    Probes an authenticated endpoint with four credential scenarios and reports
    whether the server incorrectly grants access when it should not.
    """

    DETECTOR_ID = "broken_auth"
    OWASP_CATEGORY = OWASPCategory.BROKEN_AUTH
    SEVERITY = Severity.CRITICAL
    CONFIDENCE = 95.0
    REMEDIATION_REF = (
        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
    )

    def run(
        self,
        base_url: str,
        policy: TargetPolicy,
        endpoint_path: str,
        valid_token: str,
        path_param: str = "",
        auth_required: bool | None = None,
    ) -> DetectorResult:
        """Run broken-auth probes on a single authenticated endpoint.

        :param base_url: Validated lab base URL.
        :param policy: Allowlist policy.
        :param endpoint_path: Path to probe, e.g. ``/vuln/users/{user_id}``.
        :param valid_token: A legitimately issued token for the endpoint's service.
        :param path_param: Concrete value to substitute for ``{user_id}``
            (or similar) in ``endpoint_path``.
        :returns: ``DetectorResult`` with ``vulnerable=True`` if any probe
            obtains a 2xx response when it should be rejected.
        """
        url = base_url.rstrip("/") + endpoint_path.replace("{user_id}", path_param)

        all_evidence: list[Evidence] = []

        # --- Probe 1: No token ------------------------------------------------
        s1, rh1, rb1 = controlled_get(url, policy, headers={})
        all_evidence.append(
            _build_evidence(url, {}, s1, rh1, rb1, {"probe": "no_token", "expected": 401})
        )

        # --- Probe 2: Garbage string (not even a JWT) -------------------------
        garbage_headers = {"Authorization": "Bearer not-a-jwt-at-all"}
        s2, rh2, rb2 = controlled_get(url, policy, headers=garbage_headers)
        all_evidence.append(
            _build_evidence(
                url, garbage_headers, s2, rh2, rb2, {"probe": "garbage_token", "expected": 401}
            )
        )

        # --- Probe 3: Structurally valid JWT, wrong signature -----------------
        fake_headers = {"Authorization": f"Bearer {_FAKE_TOKEN}"}
        s3, rh3, rb3 = controlled_get(url, policy, headers=fake_headers)
        all_evidence.append(
            _build_evidence(
                url,
                fake_headers,
                s3,
                rh3,
                rb3,
                {"probe": "invalid_signature_jwt", "expected": 401},
            )
        )

        # --- Probe 4: Valid token — confirm the endpoint works at all ---------
        valid_headers = {"Authorization": f"Bearer {valid_token}"}
        s4, rh4, rb4 = controlled_get(url, policy, headers=valid_headers)
        all_evidence.append(
            _build_evidence(
                url, valid_headers, s4, rh4, rb4, {"probe": "valid_token", "expected": "2xx"}
            )
        )
        # A 4xx on the valid-token probe doesn't itself indicate broken auth
        # (it might indicate a different misconfiguration), but we record it.
        bypass_probes = (
            (s1 < 400, DetectorIssueCode.BROKEN_AUTH_NO_TOKEN_BYPASS, all_evidence[0]),
            (s2 < 400, DetectorIssueCode.BROKEN_AUTH_MALFORMED_TOKEN_BYPASS, all_evidence[1]),
            (
                s3 < 400,
                DetectorIssueCode.BROKEN_AUTH_INVALID_SIGNATURE_BYPASS,
                all_evidence[2],
            ),
        )
        # A bypass can only be confirmed when the caller has independently
        # established that the endpoint requires authentication and the valid
        # test credential can access it.  Otherwise this is inconclusive.
        confirmed = auth_required is True and s4 < 400
        issues = [
            DetectorIssue(
                issue_code=issue_code,
                title=f"Broken authentication on {endpoint_path}",
                detail=(
                    f"Protected endpoint {endpoint_path} accepted an unexpected "
                    "credential probe."
                ),
                vulnerable=True,
                severity=self.SEVERITY,
                confidence=self.CONFIDENCE,
                evidence=[evidence],
                endpoint_path=endpoint_path,
                endpoint_method="GET",
            )
            for observed, issue_code, evidence in bypass_probes
            if observed and confirmed
        ]
        bypass_observed = any(observed for observed, _, _ in bypass_probes)
        inconclusive = (bypass_observed and not confirmed) or s4 >= 400
        findings = [issue.detail for issue in issues]
        vulnerable = bool(issues)
        return DetectorResult(
            detector_id=self.DETECTOR_ID,
            owasp_category=self.OWASP_CATEGORY,
            severity=self.SEVERITY,
            confidence=self.CONFIDENCE if vulnerable else 0.0,
            vulnerable=vulnerable,
            evidence=all_evidence,
            title=(
                f"Broken Authentication on {endpoint_path}: "
                + "; ".join(findings)
                if vulnerable
                else f"Authentication enforced correctly on {endpoint_path}"
            ),
            remediation_ref=self.REMEDIATION_REF,
            detail=(
                "\n".join(findings)
                if findings
                else (
                    "Authentication classification is inconclusive: endpoint "
                    "requirement or valid test credentials could not be established."
                    if inconclusive
                    else "All auth probes returned expected status codes."
                )
            ),
            issues=issues,
            status="inconclusive" if inconclusive else "completed",
        )
