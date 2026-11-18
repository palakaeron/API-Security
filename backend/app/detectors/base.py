"""Shared base types for the M4 detection engine.

All detectors return a ``DetectorResult`` containing zero or more ``Evidence``
objects.  Types are plain dataclasses — no ORM dependencies — so detectors can
be unit-tested without a database.  Persistence to the ``findings`` /
``evidence`` tables is handled by the scan-runner layer (M5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class OWASPCategory(str, Enum):
    """OWASP API Security Top-10 (2023) categories referenced by detectors."""

    BOLA = "API1:2023 Broken Object Level Authorization"
    BROKEN_AUTH = "API2:2023 Broken Authentication"
    BOPLA = "API3:2023 Broken Object Property Level Authorization"
    BFLA = "API5:2023 Broken Function Level Authorization"
    MISCONFIGURATION = "API8:2023 Security Misconfiguration"
    IMPROPER_INVENTORY = "API9:2023 Improper Inventory Management"
    # JWT/token issues are a sub-category of Broken Authentication.
    JWT = "API2:2023 Broken Authentication (JWT)"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectorIssueCode(str, Enum):
    """Stable identifiers for independently actionable detector issues."""

    BOLA_CROSS_USER_ACCESS = "bola.cross_user_access"
    BFLA_ADMIN_FUNCTION_ACCESS = "bfla.admin_function_access"
    BOPLA_SENSITIVE_PROPERTY_READ = "bopla.sensitive_property_read"
    BOPLA_PROPERTY_PRIVILEGE_ESCALATION = "bopla.property_privilege_escalation"
    BROKEN_AUTH_NO_TOKEN_BYPASS = "broken_auth.no_token_bypass"
    BROKEN_AUTH_MALFORMED_TOKEN_BYPASS = "broken_auth.malformed_token_bypass"
    BROKEN_AUTH_INVALID_SIGNATURE_BYPASS = "broken_auth.invalid_signature_bypass"
    JWT_WEAK_SIGNING_SECRET = "jwt.weak_signing_secret"
    JWT_ALG_NONE_ACCEPTED = "jwt.alg_none_accepted"
    JWT_EXCESSIVE_EXPIRY = "jwt.excessive_expiry"
    JWT_MISSING_REQUIRED_CLAIMS = "jwt.missing_required_claims"
    MISCONFIGURATION_MISSING_SECURITY_HEADERS = (
        "misconfiguration.missing_security_headers"
    )
    MISCONFIGURATION_VERBOSE_ERROR_DISCLOSURE = (
        "misconfiguration.verbose_error_disclosure"
    )
    MISCONFIGURATION_GRAPHQL_INTROSPECTION = "misconfiguration.graphql_introspection"


@dataclass
class Evidence:
    """A single observed request/response pair that supports a finding.

    ``request`` and ``response`` bodies are sanitised before being stored —
    see ``sanitiser.sanitise_body()``.  Raw token values must never appear here.
    """

    url: str
    method: str
    request_headers: dict[str, str]
    request_body: Any
    response_status: int
    response_headers: dict[str, str]
    response_body: Any
    # Free-form context: role used, which user identity, what was cross-accessed, etc.
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectorIssue:
    """One independently actionable issue reported by a detector."""

    issue_code: DetectorIssueCode | str
    title: str
    detail: str
    vulnerable: bool
    severity: Severity
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)
    endpoint_path: str | None = None
    endpoint_method: str | None = None

    def __post_init__(self) -> None:
        try:
            self.issue_code = DetectorIssueCode(self.issue_code)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported detector issue code: {self.issue_code!r}") from exc
        if not isinstance(self.severity, Severity):
            raise ValueError("issue severity must be a Severity value")
        if not isinstance(self.vulnerable, bool):
            raise ValueError("issue vulnerable flag must be boolean")
        if not isinstance(self.confidence, int | float) or not 0 <= self.confidence <= 100:
            raise ValueError("issue confidence must be between 0 and 100")


@dataclass
class DetectorResult:
    """Output of a single detector run against one endpoint or service.

    A result with ``vulnerable=True`` and non-empty ``evidence`` means the
    detector found a real signal.  ``vulnerable=False`` with empty evidence is
    a clean (expected-negative) result.

    Fields that carry OWASP / remediation metadata are set by each detector
    and are used downstream by the risk engine and AI explanation layer.
    """

    detector_id: str
    """Short snake_case identifier, e.g. ``bola``, ``broken_auth``."""

    owasp_category: OWASPCategory
    severity: Severity
    confidence: float
    """0.0–100.0 scale.  100.0 = deterministic proof; lower = heuristic."""

    vulnerable: bool
    evidence: list[Evidence] = field(default_factory=list)

    title: str = ""
    """One-line human-readable finding title."""

    remediation_ref: str = ""
    """URL or reference to remediation guidance (OWASP, CWE, RFC)."""

    detail: str = ""
    """Additional context for the AI explanation layer."""

    issues: list[DetectorIssue] = field(default_factory=list)
    """Independently actionable issues; clean runs leave this empty."""

    status: str = "completed"
    """Execution status, including ``inconclusive`` when proof is insufficient."""
