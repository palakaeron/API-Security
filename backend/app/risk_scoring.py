"""Deterministic risk scoring for confirmed security issues.

This module is intentionally independent of persistence, networking, and
detector execution.  Callers must provide already-assessed impact,
exploitability, and confidence factors.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

from app.detectors.base import Severity

SCORING_METHODOLOGY_VERSION = "1.0"
_ZERO = Decimal("0")
_ONE_HUNDRED = Decimal("100")
_ONE_DECIMAL = Decimal("0.1")

type NumericFactor = int | float | Decimal


@dataclass(frozen=True, slots=True)
class RiskScoreResult:
    """Explainable result of scoring one confirmed security issue."""

    impact: float
    exploitability: float
    confidence: float
    risk_score: float
    risk_severity: Severity
    scoring_version: str


@dataclass(frozen=True, slots=True)
class RiskFactors:
    """Central assessment factors for one supported issue code."""

    impact: float
    exploitability: float
    rationale: str


@dataclass(frozen=True, slots=True)
class FindingRiskSummary:
    """Aggregate of scored and unscored findings for one scan."""

    maximum_score: Decimal | None
    severity_counts: dict[str, int]
    has_unscored_findings: bool
    scoring_versions: frozenset[str]


@dataclass(frozen=True, slots=True)
class DetectorCoverage:
    """Execution accounting for the configured detectors in one scan."""

    configured: tuple[str, ...]
    executed: tuple[str, ...]
    skipped: tuple[str, ...]
    failed: tuple[str, ...]
    inconclusive: tuple[str, ...]
    coverage: float
    incomplete: bool


_RISK_SEVERITY_KEYS = ("critical", "high", "medium", "low", "informational")


_ISSUE_RISK_FACTORS: dict[str, RiskFactors] = {
    "bola.cross_user_access": RiskFactors(
        85, 80, "Cross-user access exposes another user's resource with an authenticated token."
    ),
    "bfla.admin_function_access": RiskFactors(
        80, 90, "A regular user can invoke a restricted administrative function directly."
    ),
    "bopla.sensitive_property_read": RiskFactors(
        75, 80, "A non-owner can read sensitive object properties through the read operation."
    ),
    "bopla.property_privilege_escalation": RiskFactors(
        100, 90, "A non-owner can modify a privileged property and escalate authority."
    ),
    "broken_auth.no_token_bypass": RiskFactors(
        100, 95, "A protected endpoint accepts a request without authentication."
    ),
    "broken_auth.malformed_token_bypass": RiskFactors(
        100, 90, "A protected endpoint accepts a malformed credential."
    ),
    "broken_auth.invalid_signature_bypass": RiskFactors(
        100, 95, "A protected endpoint accepts a credential with an invalid signature."
    ),
    "jwt.weak_signing_secret": RiskFactors(
        95, 85, "A signing secret can be recovered from the controlled weak-secret set."
    ),
    "jwt.alg_none_accepted": RiskFactors(
        100, 90, "A protected endpoint accepts an unsigned JWT."
    ),
    "jwt.excessive_expiry": RiskFactors(
        65, 70, "A token remains valid substantially longer than the configured guidance."
    ),
    "jwt.missing_required_claims": RiskFactors(
        50,
        60,
        "A JWT omits claims needed for robust issuer, audience, subject, or expiry validation.",
    ),
    "misconfiguration.missing_security_headers": RiskFactors(
        20, 35, "Missing response headers weaken browser-facing defense in depth."
    ),
    "misconfiguration.verbose_error_disclosure": RiskFactors(
        50, 70, "Error responses disclose implementation or diagnostic information."
    ),
    "misconfiguration.graphql_introspection": RiskFactors(
        60, 85, "An exposed schema makes GraphQL structure and operations easier to enumerate."
    ),
}


def get_issue_risk_factors(issue_code: str) -> RiskFactors:
    """Return centralized factors or fail explicitly for an unsupported code."""

    key = getattr(issue_code, "value", issue_code)
    try:
        return _ISSUE_RISK_FACTORS[key]
    except (KeyError, TypeError):
        raise ValueError(f"unsupported risk-scoring issue code: {issue_code!r}") from None


def aggregate_finding_risk(findings: Iterable[Any]) -> FindingRiskSummary:
    """Aggregate scored finding values without performing database access."""

    counts = {key: 0 for key in _RISK_SEVERITY_KEYS}
    maximum_score: Decimal | None = None
    has_unscored = False
    scoring_versions: set[str] = set()
    for finding in findings:
        score = getattr(finding, "risk_score", None)
        severity = getattr(finding, "risk_severity", None)
        version = getattr(finding, "scoring_version", None)
        if score is None or severity is None or version is None:
            has_unscored = True
            continue
        score_value = _validated_decimal("risk_score", score)
        severity_key = str(severity).lower()
        if severity_key == "info":
            severity_key = "informational"
        if severity_key not in counts:
            raise ValueError(f"unsupported finding risk severity: {severity!r}")
        counts[severity_key] += 1
        scoring_versions.add(str(version))
        if maximum_score is None or score_value > maximum_score:
            maximum_score = score_value

    return FindingRiskSummary(
        maximum_score=maximum_score,
        severity_counts=counts,
        has_unscored_findings=has_unscored,
        scoring_versions=frozenset(scoring_versions),
    )


def summarize_detector_coverage(
    configured_detectors: Iterable[str],
    detector_results: Iterable[Mapping[str, Any]],
) -> DetectorCoverage:
    """Classify configured detector outcomes and calculate execution coverage."""

    configured = tuple(dict.fromkeys(str(name) for name in configured_detectors))
    result_by_name = {
        str(result.get("detector")): str(result.get("status"))
        for result in detector_results
        if result.get("detector")
    }
    executed: list[str] = []
    skipped: list[str] = []
    failed: list[str] = []
    inconclusive: list[str] = []
    for name in configured:
        status = result_by_name.get(name)
        if status == "executed":
            executed.append(name)
        elif status == "skipped":
            skipped.append(name)
        elif status == "inconclusive":
            inconclusive.append(name)
        else:
            failed.append(name)

    total = len(configured)
    coverage = (len(executed) / total) if total else 0.0
    incomplete = not configured or bool(skipped or failed or inconclusive or len(executed) != total)
    return DetectorCoverage(
        configured=configured,
        executed=tuple(executed),
        skipped=tuple(skipped),
        failed=tuple(failed),
        inconclusive=tuple(inconclusive),
        coverage=coverage,
        incomplete=incomplete,
    )


def get_scoring_methodology_version() -> str:
    """Return the version of the scoring methodology used by this module."""

    return SCORING_METHODOLOGY_VERSION


def _validated_decimal(name: str, value: NumericFactor | None) -> Decimal:
    if value is None or isinstance(value, bool) or not isinstance(value, int | float | Decimal):
        raise ValueError(f"{name} must be a finite number between 0 and 100")
    try:
        decimal_value = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError(f"{name} must be a finite number between 0 and 100") from None
    if not decimal_value.is_finite() or not _ZERO <= decimal_value <= _ONE_HUNDRED:
        raise ValueError(f"{name} must be a finite number between 0 and 100")
    return decimal_value


def normalize_confidence(confidence: NumericFactor | None) -> float:
    """Validate and normalize confidence to a finite 0–100 float."""

    return float(_validated_decimal("confidence", confidence))


def map_risk_severity(risk_score: NumericFactor | None) -> Severity:
    """Map a validated 0–100 score to the approved risk severity bands."""

    score = _validated_decimal("risk_score", risk_score)
    if score == _ZERO:
        return Severity.INFO
    if score >= Decimal("90"):
        return Severity.CRITICAL
    if score >= Decimal("70"):
        return Severity.HIGH
    if score >= Decimal("40"):
        return Severity.MEDIUM
    return Severity.LOW


def calculate_risk_score(
    impact: NumericFactor | None,
    exploitability: NumericFactor | None,
    confidence: NumericFactor | None,
) -> RiskScoreResult:
    """Calculate a deterministic risk score from explicit validated factors.

    The approved formula is ``impact * 0.50 + exploitability * 0.30 +
    confidence * 0.20``.  Decimal arithmetic and ``ROUND_HALF_UP`` ensure
    that midpoint values do not depend on binary floating-point or Python's
    default banker rounding.
    """

    impact_value = _validated_decimal("impact", impact)
    exploitability_value = _validated_decimal("exploitability", exploitability)
    confidence_value = _validated_decimal("confidence", confidence)
    score = (
        impact_value * Decimal("0.50")
        + exploitability_value * Decimal("0.30")
        + confidence_value * Decimal("0.20")
    ).quantize(_ONE_DECIMAL, rounding=ROUND_HALF_UP)

    return RiskScoreResult(
        impact=float(impact_value),
        exploitability=float(exploitability_value),
        confidence=float(confidence_value),
        risk_score=float(score),
        risk_severity=map_risk_severity(score),
        scoring_version=get_scoring_methodology_version(),
    )
