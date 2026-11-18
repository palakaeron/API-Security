"""Broken Object Property Level Authorization (BOPLA) detector.

OWASP API3:2023

Strategy
--------
Two sub-checks, both using a cross-user context (attacker reads/writes
the victim's resource):

**Read probe** — GET the profile endpoint as the attacker:
- **Vulnerable signal**: response contains sensitive fields that the attacker
  should not see (e.g. ``support_pin``, ``role``, ``payment`` details beyond
  a masked reference).
- **Secure signal**: response only contains public fields (``id``, ``email``,
  ``display_name``) — no 403 necessarily, but sensitive properties are stripped.

**Write probe** — PATCH the profile endpoint as the attacker with a
role-escalation payload (``{"role": "admin"}``):
- **Vulnerable signal**: server accepts the PATCH (2xx) and the returned body
  contains ``"role": "admin"``.
- **Secure signal**: 403, or the field is silently ignored and the returned role
  is unchanged.

Either a read or a write finding is sufficient to flag the endpoint as
vulnerable.  Confidence is 95.0 for the write sub-check (deterministic proof of
privilege escalation) and 80.0 for the read sub-check (heuristic — the presence
of a ``support_pin`` field is a reliable indicator for this specific lab).
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
from app.detectors.http_client import controlled_get, controlled_patch
from app.detectors.sanitiser import sanitise_body, sanitise_headers
from app.security.target_allowlist import TargetPolicy

# Sensitive fields that should NOT be visible to a cross-user attacker.
_SENSITIVE_READ_FIELDS = frozenset({"support_pin", "balance_cents"})
# Field/value combinations that indicate a successful write-privilege escalation.
_ESCALATION_FIELD = "role"
_ESCALATION_VALUE = "admin"


class BoplaDetector:
    """Broken Object Property Level Authorization (BOPLA) detector.

    Checks both excessive data exposure (sensitive property read by non-owner)
    and mass-assignment / privilege-escalation (sensitive property written by
    non-owner).
    """

    DETECTOR_ID = "bopla"
    OWASP_CATEGORY = OWASPCategory.BOPLA
    REMEDIATION_REF = (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa3-broken-object-property-level-authorization/"
    )

    def run(
        self,
        base_url: str,
        policy: TargetPolicy,
        attacker_token: str,
        victim_id: str,
        read_path: str,
        write_path: str,
    ) -> DetectorResult:
        """Run BOPLA read and write probes on profile-style endpoints.

        :param base_url: Validated lab base URL.
        :param policy: Allowlist policy.
        :param attacker_token: JWT for the authenticated attacker (non-owner).
        :param victim_id: ID of the victim whose profile is being accessed.
        :param read_path: Path template for GET, e.g. ``/vuln/profiles/{user_id}``.
        :param write_path: Path template for PATCH, e.g. ``/vuln/profiles/{user_id}``.
        :returns: ``DetectorResult`` summarising both sub-checks.
        """
        auth_headers = {"Authorization": f"Bearer {attacker_token}"}
        safe_auth = sanitise_headers(auth_headers)

        read_url = base_url.rstrip("/") + read_path.replace("{user_id}", victim_id)
        write_url = base_url.rstrip("/") + write_path.replace("{user_id}", victim_id)

        findings: list[str] = []
        all_evidence: list[Evidence] = []
        max_confidence = 0.0
        max_severity = Severity.MEDIUM

        # ── Read probe ────────────────────────────────────────────────────────
        rs, rh, rb = controlled_get(read_url, policy, headers=auth_headers)
        read_sensitive_exposed: list[str] = []
        if rs == 200 and isinstance(rb, dict):
            read_sensitive_exposed = [f for f in _SENSITIVE_READ_FIELDS if f in rb]

        all_evidence.append(
            Evidence(
                url=read_url,
                method="GET",
                request_headers=safe_auth,
                request_body=None,
                response_status=rs,
                response_headers=rh,
                response_body=rb,
                context={
                    "probe": "read",
                    "victim_id": victim_id,
                    "sensitive_fields_exposed": read_sensitive_exposed,
                    "detector": self.DETECTOR_ID,
                },
            )
        )
        if read_sensitive_exposed:
            findings.append(
                f"read probe: sensitive fields {read_sensitive_exposed!r} "
                f"exposed to non-owner (HTTP {rs})"
            )
            max_confidence = max(max_confidence, 80.0)
            max_severity = Severity.HIGH

        # ── Write probe ───────────────────────────────────────────────────────
        escalation_payload = {_ESCALATION_FIELD: _ESCALATION_VALUE}
        ws, wh, wb = controlled_patch(
            write_url, policy, headers=auth_headers, json=escalation_payload
        )
        write_escalated = False
        if ws < 400 and isinstance(wb, dict):
            # Check both top-level and nested 'profile' key
            returned_role = wb.get(_ESCALATION_FIELD) or wb.get("profile", {}).get(
                _ESCALATION_FIELD
            )
            write_escalated = returned_role == _ESCALATION_VALUE

        all_evidence.append(
            Evidence(
                url=write_url,
                method="PATCH",
                request_headers=safe_auth,
                request_body=sanitise_body(escalation_payload),
                response_status=ws,
                response_headers=wh,
                response_body=wb,
                context={
                    "probe": "write_escalation",
                    "victim_id": victim_id,
                    "payload": escalation_payload,
                    "escalation_succeeded": write_escalated,
                    "detector": self.DETECTOR_ID,
                },
            )
        )
        if write_escalated:
            findings.append(
                f"write probe: role-escalation payload accepted "
                f"(HTTP {ws}, returned role=admin)"
            )
            max_confidence = max(max_confidence, 95.0)
            max_severity = Severity.CRITICAL

        vulnerable = bool(findings)
        issues: list[DetectorIssue] = []
        if read_sensitive_exposed:
            issues.append(
                DetectorIssue(
                    issue_code=DetectorIssueCode.BOPLA_SENSITIVE_PROPERTY_READ,
                    title=f"BOPLA: sensitive properties exposed on {read_path}",
                    detail=(
                        f"Sensitive fields {read_sensitive_exposed!r} were returned "
                        "to a non-owner by the GET probe."
                    ),
                    vulnerable=True,
                    severity=Severity.HIGH,
                    confidence=80.0,
                    evidence=[all_evidence[0]],
                    endpoint_path=read_path,
                    endpoint_method="GET",
                )
            )
        if write_escalated:
            issues.append(
                DetectorIssue(
                    issue_code=DetectorIssueCode.BOPLA_PROPERTY_PRIVILEGE_ESCALATION,
                    title=f"BOPLA: privileged property modification on {write_path}",
                    detail=(
                        "A non-owner successfully changed the privileged role "
                        "property through the PATCH probe."
                    ),
                    vulnerable=True,
                    severity=Severity.CRITICAL,
                    confidence=95.0,
                    evidence=[all_evidence[1]],
                    endpoint_path=write_path,
                    endpoint_method="PATCH",
                )
            )
        return DetectorResult(
            detector_id=self.DETECTOR_ID,
            owasp_category=self.OWASP_CATEGORY,
            severity=max_severity if vulnerable else Severity.INFO,
            confidence=max_confidence if vulnerable else 0.0,
            vulnerable=vulnerable,
            evidence=all_evidence,
            title=(
                f"BOPLA on {read_path}: " + "; ".join(findings)
                if vulnerable
                else f"BOPLA: {read_path} enforces property-level authorization"
            ),
            remediation_ref=self.REMEDIATION_REF,
            detail=(
                "\n".join(findings)
                if findings
                else "Read returned only public fields; write was rejected or field ignored."
            ),
            issues=issues,
        )
