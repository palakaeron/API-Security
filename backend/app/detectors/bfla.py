"""Broken Function Level Authorization (BFLA) detector.

OWASP API5:2023

Strategy
--------
The detector authenticates as a **regular user** (non-admin) and attempts to
invoke an endpoint that is designed to require an **admin role**.

- **Vulnerable signal**: server returns HTTP 2xx — a regular user successfully
  called an admin-only function.
- **Expected-negative (secure) signal**: server returns HTTP 403.

The test is one-directional (regular → admin) because the inverse (admin can
reach admin endpoints) is expected behaviour, not a finding.
"""

from __future__ import annotations

from app.detectors.base import DetectorResult, Evidence, OWASPCategory, Severity
from app.detectors.http_client import controlled_get
from app.detectors.sanitiser import sanitise_headers
from app.security.target_allowlist import TargetPolicy


class BflaDetector:
    """Broken Function Level Authorization (BFLA) detector.

    Sends a request to an admin-only function using a regular-user token and
    checks whether the server enforces the required role.
    """

    DETECTOR_ID = "bfla"
    OWASP_CATEGORY = OWASPCategory.BFLA
    SEVERITY = Severity.HIGH
    CONFIDENCE = 95.0
    REMEDIATION_REF = (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa5-broken-function-level-authorization/"
    )

    def run(
        self,
        base_url: str,
        policy: TargetPolicy,
        regular_user_token: str,
        admin_endpoint_path: str,
    ) -> DetectorResult:
        """Test whether a regular user can access an admin-only function.

        :param base_url: Validated lab base URL.
        :param policy: Allowlist policy.
        :param regular_user_token: JWT for a user without admin privileges.
        :param admin_endpoint_path: Path to the admin function, e.g.
            ``/vuln/admin/audit``.
        :returns: ``DetectorResult`` with ``vulnerable=True`` if the server
            returned 2xx for a non-admin user's request.
        """
        url = base_url.rstrip("/") + admin_endpoint_path
        headers = {"Authorization": f"Bearer {regular_user_token}"}

        status, resp_headers, resp_body = controlled_get(url, policy, headers=headers)

        vulnerable = status < 400

        evidence = Evidence(
            url=url,
            method="GET",
            request_headers=sanitise_headers(headers),
            request_body=None,
            response_status=status,
            response_headers=resp_headers,
            response_body=resp_body,
            context={
                "role_used": "user",
                "required_role": "admin",
                "endpoint": admin_endpoint_path,
                "detector": self.DETECTOR_ID,
            },
        )

        return DetectorResult(
            detector_id=self.DETECTOR_ID,
            owasp_category=self.OWASP_CATEGORY,
            severity=self.SEVERITY,
            confidence=self.CONFIDENCE if vulnerable else 0.0,
            vulnerable=vulnerable,
            evidence=[evidence],
            title=(
                f"BFLA: regular user accessed admin function {admin_endpoint_path}"
                if vulnerable
                else f"BFLA: {admin_endpoint_path} correctly requires admin role"
            ),
            remediation_ref=self.REMEDIATION_REF,
            detail=(
                f"A request with a regular-user token returned HTTP {status} on "
                f"an admin-only endpoint ({admin_endpoint_path}). "
                "Server-side role validation is missing or insufficient."
                if vulnerable
                else f"Server returned HTTP {status} — function-level role check is enforced."
            ),
        )
