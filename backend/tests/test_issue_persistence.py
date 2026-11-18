from threading import Barrier, Thread

import pytest
from app.database import Base, get_engine
from app.detectors.base import (
    DetectorIssue,
    DetectorIssueCode,
    DetectorResult,
    OWASPCategory,
    Severity,
)
from app.detectors.base import (
    Evidence as DetectorEvidence,
)
from app.models import Api, Endpoint, Evidence, Finding, Project, Scan, User
from app.risk_scoring import get_issue_risk_factors
from sqlalchemy.orm import Session


@pytest.fixture
def issue_database(tmp_path):
    engine = get_engine(f"sqlite:///{tmp_path / 'issue-persistence.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        user = User(id=1, email="issue-owner@example.test", password_hash="hash")
        project = Project(name="Issue project", owner=user)
        api = Api(name="Issue API", project=project, base_url="http://127.0.0.1:8101")
        read_endpoint = Endpoint(
            api=api, path="/profiles/{user_id}", method="GET", source="spec"
        )
        write_endpoint = Endpoint(
            api=api, path="/profiles/{user_id}", method="PATCH", source="spec"
        )
        scan = Scan(api=api, configuration={"detectors": ["bopla"]})
        db.add_all([user, project, api, read_endpoint, write_endpoint, scan])
        db.commit()
        return engine, scan.id, read_endpoint.id, write_endpoint.id


@pytest.mark.parametrize(
    ("issue_code", "impact", "exploitability"),
    [
        ("bola.cross_user_access", 85, 80),
        ("bfla.admin_function_access", 80, 90),
        ("bopla.sensitive_property_read", 75, 80),
        ("bopla.property_privilege_escalation", 100, 90),
        ("broken_auth.no_token_bypass", 100, 95),
        ("broken_auth.malformed_token_bypass", 100, 90),
        ("broken_auth.invalid_signature_bypass", 100, 95),
        ("jwt.weak_signing_secret", 95, 85),
        ("jwt.alg_none_accepted", 100, 90),
        ("jwt.excessive_expiry", 65, 70),
        ("jwt.missing_required_claims", 50, 60),
        ("misconfiguration.missing_security_headers", 20, 35),
        ("misconfiguration.verbose_error_disclosure", 50, 70),
        ("misconfiguration.graphql_introspection", 60, 85),
    ],
)
def test_every_issue_code_has_centralized_factors(issue_code, impact, exploitability) -> None:
    factors = get_issue_risk_factors(issue_code)

    assert (factors.impact, factors.exploitability) == (impact, exploitability)
    assert factors.rationale


def test_unknown_issue_code_fails_without_arbitrary_score() -> None:
    with pytest.raises(ValueError, match="unsupported risk-scoring issue code"):
        get_issue_risk_factors("unknown.issue")


def _issue(code: DetectorIssueCode, path: str, method: str, evidence: DetectorEvidence):
    return DetectorIssue(
        issue_code=code,
        title="confirmed issue",
        detail="confirmed by synthetic evidence",
        vulnerable=True,
        severity=Severity.HIGH,
        confidence=95.0,
        evidence=[evidence],
        endpoint_path=path,
        endpoint_method=method,
    )


def test_issue_persistence_scores_each_issue_and_sanitizes_evidence(issue_database) -> None:
    engine, scan_id, read_id, write_id = issue_database
    read_evidence = DetectorEvidence(
        url="http://127.0.0.1:8101/profiles/bob",
        method="GET",
        request_headers={"Authorization": "Bearer raw-token"},
        request_body=None,
        response_status=200,
        response_headers={},
        response_body={"support_pin": "1234"},
        context={"probe": "read"},
    )
    write_evidence = DetectorEvidence(
        url="http://127.0.0.1:8101/profiles/bob",
        method="PATCH",
        request_headers={},
        request_body={"password": "raw-password", "role": "admin"},
        response_status=200,
        response_headers={},
        response_body={"role": "admin"},
        context={"probe": "write_escalation"},
    )
    result = DetectorResult(
        detector_id="bopla",
        owasp_category=OWASPCategory.BOPLA,
        severity=Severity.CRITICAL,
        confidence=95.0,
        vulnerable=True,
        issues=[
            _issue(
                DetectorIssueCode.BOPLA_SENSITIVE_PROPERTY_READ,
                "/profiles/{user_id}",
                "GET",
                read_evidence,
            ),
            _issue(
                DetectorIssueCode.BOPLA_PROPERTY_PRIVILEGE_ESCALATION,
                "/profiles/{user_id}",
                "PATCH",
                write_evidence,
            ),
        ],
    )
    assert len(result.issues) == 2

    from app import scan_runner

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        endpoints = list(db.query(Endpoint).filter_by(api_id=scan.api_id).all())
        count, errors = scan_runner._persist_detector_result(db, scan, result, endpoints)
        db.commit()

        findings = db.query(Finding).filter_by(scan_id=scan_id).order_by(Finding.id).all()
        evidence = [db.query(Evidence).filter_by(finding_id=item.id).one() for item in findings]

    assert count == 2
    assert errors == []
    assert {item.endpoint_id for item in findings} == {read_id, write_id}
    assert {item.issue_code for item in findings} == {
        "bopla.sensitive_property_read",
        "bopla.property_privilege_escalation",
    }, [item.__dict__ for item in findings]
    assert all(item.risk_score is not None for item in findings)
    assert all(item.risk_severity is not None for item in findings)
    assert all(item.scoring_version == "1.0" for item in findings)
    assert all(item.impact is not None and item.exploitability is not None for item in findings)
    assert all(item.severity == "high" for item in findings)
    assert {item.request["method"] for item in evidence} == {"GET", "PATCH"}
    assert evidence[0].request["headers"]["Authorization"] == "[REDACTED]"
    assert evidence[1].request["body"]["password"] == "[REDACTED]"


def test_modern_identity_deduplicates_without_overwriting_evidence(issue_database) -> None:
    engine, scan_id, read_id, _ = issue_database
    evidence = DetectorEvidence(
        url="http://127.0.0.1:8101/profiles/bob",
        method="GET",
        request_headers={},
        request_body=None,
        response_status=200,
        response_headers={},
        response_body={"support_pin": "1234"},
        context={"probe": "read"},
    )
    issue = _issue(
        DetectorIssueCode.BOPLA_SENSITIVE_PROPERTY_READ,
        "/profiles/{user_id}",
        "GET",
        evidence,
    )
    result = DetectorResult(
        detector_id="bopla",
        owasp_category=OWASPCategory.BOPLA,
        severity=Severity.HIGH,
        confidence=80.0,
        vulnerable=True,
        issues=[issue],
    )

    from app import scan_runner

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        endpoints = list(db.query(Endpoint).filter_by(api_id=scan.api_id).all())
        assert scan_runner._persist_detector_result(db, scan, result, endpoints) == (1, [])
        db.commit()
        assert scan_runner._persist_detector_result(db, scan, result, endpoints) == (0, [])
        db.commit()
        finding = db.query(Finding).filter_by(scan_id=scan_id).one()

        assert finding.endpoint_id == read_id
        assert finding.finding_identity
        assert db.query(Evidence).filter_by(finding_id=finding.id).count() == 1


def test_legacy_aggregate_result_does_not_receive_modern_risk_fields(issue_database) -> None:
    engine, scan_id, read_id, _ = issue_database
    result = DetectorResult(
        detector_id="legacy",
        owasp_category=OWASPCategory.BOLA,
        severity=Severity.HIGH,
        confidence=95.0,
        vulnerable=True,
    )

    from app import scan_runner

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        endpoint = db.get(Endpoint, read_id)
        assert scan_runner._persist_detector_result(
            db, scan, result, [endpoint], legacy_endpoint=endpoint
        ) == (1, [])
        db.commit()
        finding = db.query(Finding).filter_by(scan_id=scan_id).one()

    assert finding.issue_code is None
    assert finding.finding_identity is None
    assert finding.risk_score is None
    assert finding.scoring_version is None


def test_concurrent_modern_identity_conflict_keeps_one_finding(issue_database) -> None:
    engine, scan_id, read_id, _ = issue_database
    evidence = DetectorEvidence(
        url="http://127.0.0.1:8101/profiles/bob",
        method="GET",
        request_headers={},
        request_body=None,
        response_status=200,
        response_headers={},
        response_body={"support_pin": "1234"},
        context={"probe": "read"},
    )
    issue = _issue(
        DetectorIssueCode.BOPLA_SENSITIVE_PROPERTY_READ,
        "/profiles/{user_id}",
        "GET",
        evidence,
    )
    result = DetectorResult(
        detector_id="bopla",
        owasp_category=OWASPCategory.BOPLA,
        severity=Severity.HIGH,
        confidence=80.0,
        vulnerable=True,
        issues=[issue],
    )
    barrier = Barrier(2)
    counts: list[tuple[int, list[str]]] = []

    def persist() -> None:
        with Session(engine) as db:
            scan = db.get(Scan, scan_id)
            endpoint = db.get(Endpoint, read_id)
            assert scan is not None and endpoint is not None
            barrier.wait(timeout=3)
            counts.append(
                scan_runner._persist_detector_result(db, scan, result, [endpoint])
            )
            db.commit()

    from app import scan_runner

    workers = [Thread(target=persist) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)

    assert all(not worker.is_alive() for worker in workers)
    assert sorted(counts, key=lambda item: item[0]) == [(0, []), (1, [])]
    with Session(engine) as db:
        assert db.query(Finding).filter_by(scan_id=scan_id).count() == 1
