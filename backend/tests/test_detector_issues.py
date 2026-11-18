from time import time
from types import SimpleNamespace

import jwt
import pytest
from app.detectors.base import (
    DetectorIssue,
    DetectorIssueCode,
    DetectorResult,
    Evidence,
    OWASPCategory,
    Severity,
)
from app.detectors.bfla import BflaDetector
from app.detectors.bola import BolaDetector
from app.detectors.bopla import BoplaDetector
from app.detectors.broken_auth import BrokenAuthDetector
from app.detectors.jwt_analyzer import JwtAnalyzer
from app.detectors.misconfiguration import MisconfigurationDetector

POLICY = SimpleNamespace()


def _evidence(status: int, method: str = "GET") -> tuple[int, dict, dict]:
    return status, {}, {"id": "victim", "role": "admin"}


def test_detector_issue_validates_codes_and_old_result_shape_remains_valid() -> None:
    evidence = Evidence("http://test", "GET", {}, None, 200, {}, {})
    issue = DetectorIssue(
        issue_code="bola.cross_user_access",
        title="title",
        detail="detail",
        vulnerable=True,
        severity=Severity.HIGH,
        confidence=95.0,
        evidence=[evidence],
    )
    result = DetectorResult(
        detector_id="legacy",
        owasp_category=OWASPCategory.BOLA,
        severity=Severity.INFO,
        confidence=0.0,
        vulnerable=False,
    )

    assert issue.issue_code is DetectorIssueCode.BOLA_CROSS_USER_ACCESS
    assert result.issues == []

    with pytest.raises(ValueError):
        DetectorIssue("unknown.issue", "title", "detail", True, Severity.LOW, 10.0)


def test_bola_emits_issue_with_its_evidence(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.detectors.bola.controlled_get",
        lambda *args, **kwargs: (200, {}, {"id": "victim"}),
    )

    result = BolaDetector().run("http://test", POLICY, "token", "victim", "/users/{user_id}")

    assert [issue.issue_code for issue in result.issues] == [
        DetectorIssueCode.BOLA_CROSS_USER_ACCESS
    ]
    assert result.issues[0].evidence == result.evidence


def test_bfla_denial_emits_no_vulnerable_issue(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.detectors.bfla.controlled_get",
        lambda *args, **kwargs: (403, {}, {}),
    )

    result = BflaDetector().run("http://test", POLICY, "token", "/admin")

    assert result.vulnerable is False
    assert result.issues == []


def test_bopla_read_and_write_are_separate_issues(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.detectors.bopla.controlled_get",
        lambda *args, **kwargs: (200, {}, {"support_pin": "redacted"}),
    )
    monkeypatch.setattr(
        "app.detectors.bopla.controlled_patch",
        lambda *args, **kwargs: (200, {}, {"role": "admin"}),
    )

    result = BoplaDetector().run(
        "http://test", POLICY, "token", "victim", "/profiles/{user_id}", "/profiles/{user_id}"
    )

    assert [issue.issue_code for issue in result.issues] == [
        DetectorIssueCode.BOPLA_SENSITIVE_PROPERTY_READ,
        DetectorIssueCode.BOPLA_PROPERTY_PRIVILEGE_ESCALATION,
    ]
    assert result.issues[0].evidence[0].method == "GET"
    assert result.issues[1].evidence[0].method == "PATCH"


def test_broken_auth_requires_explicit_protected_endpoint(monkeypatch) -> None:
    responses = iter([(200, {}, {}), (200, {}, {}), (200, {}, {}), (200, {}, {})])
    monkeypatch.setattr(
        "app.detectors.broken_auth.controlled_get", lambda *args, **kwargs: next(responses)
    )

    result = BrokenAuthDetector().run(
        "http://test", POLICY, "/protected", "valid", auth_required=None
    )

    assert result.vulnerable is False
    assert result.issues == []
    assert result.status == "inconclusive"


def test_broken_auth_confirmed_bypasses_have_independent_codes(monkeypatch) -> None:
    responses = iter([(200, {}, {}), (200, {}, {}), (200, {}, {}), (200, {}, {})])
    monkeypatch.setattr(
        "app.detectors.broken_auth.controlled_get", lambda *args, **kwargs: next(responses)
    )

    result = BrokenAuthDetector().run(
        "http://test", POLICY, "/protected", "valid", auth_required=True
    )

    assert [issue.issue_code for issue in result.issues] == [
        DetectorIssueCode.BROKEN_AUTH_NO_TOKEN_BYPASS,
        DetectorIssueCode.BROKEN_AUTH_MALFORMED_TOKEN_BYPASS,
        DetectorIssueCode.BROKEN_AUTH_INVALID_SIGNATURE_BYPASS,
    ]
    assert all(issue.evidence[0].method == "GET" for issue in result.issues)


def test_broken_auth_valid_token_failure_is_inconclusive(monkeypatch) -> None:
    responses = iter([(200, {}, {}), (401, {}, {}), (401, {}, {}), (401, {}, {})])
    monkeypatch.setattr(
        "app.detectors.broken_auth.controlled_get", lambda *args, **kwargs: next(responses)
    )

    result = BrokenAuthDetector().run(
        "http://test", POLICY, "/protected", "invalid", auth_required=True
    )

    assert result.vulnerable is False
    assert result.issues == []
    assert result.status == "inconclusive"


def test_jwt_weak_secret_alg_none_expiry_and_claims_are_independent(monkeypatch) -> None:
    token = jwt.encode(
        {"sub": "alice", "exp": int(time()) + 48 * 60 * 60},
        "lab-only-weak-secret",
        algorithm="HS256",
    )
    monkeypatch.setattr(
        "app.detectors.jwt_analyzer.controlled_post_raw",
        lambda *args, **kwargs: (200, {}, {"access_token": token}),
    )
    monkeypatch.setattr(
        "app.detectors.jwt_analyzer.controlled_get",
        lambda *args, **kwargs: (200, {}, {"ok": True}),
    )

    result = JwtAnalyzer().run(
        "http://test",
        POLICY,
        "/auth/token",
        {"username": "alice", "password": "secret"},
        "/users/{user_id}",
        "alice",
    )

    assert {issue.issue_code for issue in result.issues} == {
        DetectorIssueCode.JWT_WEAK_SIGNING_SECRET,
        DetectorIssueCode.JWT_ALG_NONE_ACCEPTED,
        DetectorIssueCode.JWT_EXCESSIVE_EXPIRY,
        DetectorIssueCode.JWT_MISSING_REQUIRED_CLAIMS,
    }
    assert all(issue.evidence for issue in result.issues)


def test_misconfiguration_probes_are_independent(monkeypatch) -> None:
    def fake_get(*args, **kwargs):
        return 200, {}, {}

    def fake_post(url, *args, **kwargs):
        if url.endswith("/graphql"):
            return 200, {}, {"data": {"__schema": {"queryType": {"name": "Query"}}}}
        return 500, {}, {"traceback": "synthetic"}

    monkeypatch.setattr("app.detectors.misconfiguration.controlled_get", fake_get)
    monkeypatch.setattr("app.detectors.misconfiguration.controlled_post", fake_post)

    result = MisconfigurationDetector().run(
        "http://test", POLICY, "/health", "/graphql"
    )

    assert {issue.issue_code for issue in result.issues} == {
        DetectorIssueCode.MISCONFIGURATION_MISSING_SECURITY_HEADERS,
        DetectorIssueCode.MISCONFIGURATION_VERBOSE_ERROR_DISCLOSURE,
        DetectorIssueCode.MISCONFIGURATION_GRAPHQL_INTROSPECTION,
    }
    assert all(issue.evidence for issue in result.issues)
