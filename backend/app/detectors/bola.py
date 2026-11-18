"""BOLA — Broken Object Level Authorization detector.

OWASP API1:2023

Strategy
--------
The detector authenticates as two distinct users (the "attacker" and the
"victim"), then requests a resource owned by the victim using the attacker's
token.

- **Vulnerable signal**: the server returns HTTP 200 and the response body
  contains the victim's resource (confirmed by checking that the returned
  ``id`` / ``owner_id`` field matches the victim's identifier).
- **Expected-negative (secure) signal**: the server returns HTTP 403 or 401.

A finding is only raised when the cross-access succeeds (200) AND the returned
object belongs to the victim — not merely when a 200 is returned — to avoid
false positives on endpoints that return empty or partial results.

Usage
-----
::

    from app.detectors.bola import BolаDetector
    from app.security.target_allowlist import TargetPolicy

    policy = TargetPolicy.from_strings("127.0.0.1", "127.0.0.0/8")
    result = BolaDetector().run(
        base_url="http://127.0.0.1:8102",
        policy=policy,
        attacker_token="<alice_token>",
        victim_id="bob",
        endpoint_path="/vuln/users/{user_id}",
        victim_id_field="id",
    )
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


class BolaDetector:
    """Broken Object Level Authorization (BOLA / IDOR) detector.

    Performs a cross-user access test: authenticates as one user, requests a
    resource owned by a different user, and checks whether the server enforces
    ownership.
    """

    DETECTOR_ID = "bola"
    OWASP_CATEGORY = OWASPCategory.BOLA
    SEVERITY = Severity.HIGH
    CONFIDENCE = 95.0  # deterministic: 200 + victim's ID in body = real BOLA
    REMEDIATION_REF = (
        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
    )

    def run(
        self,
        base_url: str,
        policy: TargetPolicy,
        attacker_token: str,
        victim_id: str,
        endpoint_path: str,
        victim_id_field: str = "id",
    ) -> DetectorResult:
        """Run a BOLA cross-access test on a single endpoint.

        :param base_url: Validated lab base URL (e.g. ``http://127.0.0.1:8102``).
        :param policy: Allowlist policy — passed to the HTTP client.
        :param attacker_token: JWT for the authenticated attacker (user A).
        :param victim_id: The ID of the resource owner (user B) being accessed.
        :param endpoint_path: Path template with ``{user_id}`` substituted for
            ``victim_id``, e.g. ``/vuln/users/{user_id}``.
        :param victim_id_field: Key in the response JSON that should contain
            the victim's ID; used to confirm the resource was actually returned
            rather than an unrelated 200 response.
        :returns: ``DetectorResult`` with ``vulnerable=True`` if cross-access
            succeeded; ``vulnerable=False`` if access was denied.
        """
        url = base_url.rstrip("/") + endpoint_path.replace("{user_id}", victim_id)
        auth_headers = {"Authorization": f"Bearer {attacker_token}"}

        status, resp_headers, resp_body = controlled_get(url, policy, headers=auth_headers)

        # Sanitise for evidence storage — attacker token must not appear.
        safe_req_headers = sanitise_headers(auth_headers)

        evidence = Evidence(
            url=url,
            method="GET",
            request_headers=safe_req_headers,
            request_body=None,
            response_status=status,
            response_headers=resp_headers,
            response_body=resp_body,
            context={
                "attacker": "authenticated_user",
                "victim_id": victim_id,
                "endpoint": endpoint_path,
                "detector": self.DETECTOR_ID,
            },
        )

        # Cross-access is confirmed only when the response is 200 AND the
        # returned body contains the victim's identifier.  A 200 with an empty
        # body or the attacker's own data is not BOLA.
        vulnerable = False
        if status == 200 and isinstance(resp_body, dict):
            # Check top-level field or owner_id field
            returned_id = resp_body.get(victim_id_field) or resp_body.get("owner_id")
            if returned_id is not None and str(returned_id) == str(victim_id):
                vulnerable = True

        return DetectorResult(
            detector_id=self.DETECTOR_ID,
            owasp_category=self.OWASP_CATEGORY,
            severity=self.SEVERITY,
            confidence=self.CONFIDENCE if vulnerable else 0.0,
            vulnerable=vulnerable,
            evidence=[evidence],
            title=(
                f"BOLA: cross-user access to {endpoint_path} succeeded"
                if vulnerable
                else f"BOLA: {endpoint_path} correctly denied cross-user access"
            ),
            remediation_ref=self.REMEDIATION_REF,
            detail=(
                f"Attacker authenticated as a different user retrieved "
                f"resource owned by victim_id={victim_id!r} via {endpoint_path}. "
                f"The server returned HTTP {status} without checking object ownership."
                if vulnerable
                else f"Server returned HTTP {status} — ownership check is enforced."
            ),
            issues=(
                [
                    DetectorIssue(
                        issue_code=DetectorIssueCode.BOLA_CROSS_USER_ACCESS,
                        title=f"BOLA: cross-user access to {endpoint_path} succeeded",
                        detail=(
                            f"Attacker accessed the victim resource via {endpoint_path}; "
                            f"the server returned HTTP {status}."
                        ),
                        vulnerable=True,
                        severity=self.SEVERITY,
                        confidence=self.CONFIDENCE,
                        evidence=[evidence],
                        endpoint_path=endpoint_path,
                        endpoint_method="GET",
                    )
                ]
                if vulnerable
                else []
            ),
        )
