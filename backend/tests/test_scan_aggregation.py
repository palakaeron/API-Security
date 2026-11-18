from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace

import pytest
from app.database import Base, get_engine
from app.models import Api, Endpoint, Finding, Project, Scan, ScanHistory, User
from app.risk_scoring import aggregate_finding_risk, summarize_detector_coverage
from sqlalchemy.orm import Session


def test_detector_coverage_tracks_all_outcomes() -> None:
    coverage = summarize_detector_coverage(
        ["bola", "bfla", "bopla", "broken_auth", "jwt_analyzer"],
        [
            {"detector": "bola", "status": "executed"},
            {"detector": "bfla", "status": "skipped"},
            {"detector": "bopla", "status": "failed"},
            {"detector": "broken_auth", "status": "inconclusive"},
        ],
    )

    assert coverage.configured == ("bola", "bfla", "bopla", "broken_auth", "jwt_analyzer")
    assert coverage.executed == ("bola",)
    assert coverage.skipped == ("bfla",)
    assert coverage.failed == ("bopla", "jwt_analyzer")
    assert coverage.inconclusive == ("broken_auth",)
    assert coverage.coverage == pytest.approx(0.2)
    assert coverage.incomplete is True


def test_finding_aggregation_counts_severities_and_uses_maximum() -> None:
    findings = [
        SimpleNamespace(risk_score=Decimal("71.5"), risk_severity="high", scoring_version="1.0"),
        SimpleNamespace(
            risk_score=Decimal("96.0"), risk_severity="critical", scoring_version="1.0"
        ),
        SimpleNamespace(risk_score=Decimal("36.5"), risk_severity="low", scoring_version="1.0"),
        SimpleNamespace(risk_score=Decimal("0.0"), risk_severity="info", scoring_version="1.0"),
    ]

    summary = aggregate_finding_risk(findings)

    assert summary.maximum_score == Decimal("96.0")
    assert summary.severity_counts == {
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 1,
        "informational": 1,
    }
    assert summary.has_unscored_findings is False


def test_unscored_finding_prevents_clean_scan_aggregation() -> None:
    summary = aggregate_finding_risk(
        [SimpleNamespace(risk_score=None, risk_severity=None, scoring_version=None)]
    )

    assert summary.maximum_score is None
    assert summary.has_unscored_findings is True


@pytest.fixture
def aggregation_database(tmp_path):
    engine = get_engine(f"sqlite:///{tmp_path / 'aggregation.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        user = User(id=1, email="aggregation@example.test", password_hash="hash")
        project = Project(name="Aggregation project", owner=user)
        api = Api(name="Aggregation API", project=project, base_url="http://127.0.0.1:8101")
        endpoint = Endpoint(api=api, path="/health", method="GET", source="spec")
        db.add_all([user, project, api, endpoint])
        db.commit()
        return engine, api.id, endpoint.id


def _new_scan(db: Session, api_id: int, results: list[dict], *, status: str = "running") -> Scan:
    scan = Scan(
        api_id=api_id,
        status=status,
        configuration={"detectors": ["bola", "bfla"]},
        detector_results=results,
        assessment_status="complete",
    )
    db.add(scan)
    db.flush()
    return scan


def _add_finding(
    db: Session,
    scan_id: int,
    endpoint_id: int,
    score: str,
    severity: str,
    *,
    version: str = "1.0",
) -> None:
    db.add(
        Finding(
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            category="API1:2023 Broken Object Level Authorization",
            severity="high",
            confidence=95,
            risk_score=Decimal(score),
            risk_severity=severity,
            scoring_version=version,
            issue_code=f"test.{score}",
            impact=85,
            exploitability=80,
            finding_identity=f"test-{scan_id}-{score}-{version}",
        )
    )


def test_completed_scan_gets_maximum_score_and_history_delta(aggregation_database) -> None:
    engine, api_id, endpoint_id = aggregation_database
    from app.scan_runner import _finalize_scan

    with Session(engine) as db:
        previous = _new_scan(
            db,
            api_id,
            [
                {"detector": "bola", "status": "executed"},
                {"detector": "bfla", "status": "executed"},
            ],
            status="completed",
        )
        previous.score = Decimal("50.0")
        previous.scoring_version = "1.0"
        previous.completed_at = datetime.now(UTC)
        db.add(previous)
        current = _new_scan(
            db,
            api_id,
            [
                {"detector": "bola", "status": "executed"},
                {"detector": "bfla", "status": "executed"},
            ],
        )
        _add_finding(db, current.id, endpoint_id, "71.5", "high")
        _add_finding(db, current.id, endpoint_id, "96.0", "critical")
        db.commit()

        assert _finalize_scan(db, current.id, "completed") is True
        loaded = db.get(Scan, current.id)
        history = db.query(ScanHistory).filter_by(scan_id=current.id).one()

    assert loaded.score == Decimal("96.00")
    assert loaded.scoring_version == "1.0"
    assert loaded.assessment_status == "complete"
    assert history.previous_score == Decimal("50.00")
    assert history.current_score == Decimal("96.00")
    assert history.delta == Decimal("46.00")


def test_completed_scan_without_findings_has_zero_score(aggregation_database) -> None:
    engine, api_id, _ = aggregation_database
    from app.scan_runner import _finalize_scan

    with Session(engine) as db:
        scan = _new_scan(
            db,
            api_id,
            [
                {"detector": "bola", "status": "executed"},
                {"detector": "bfla", "status": "executed"},
            ],
        )
        db.commit()
        _finalize_scan(db, scan.id, "completed")
        loaded = db.get(Scan, scan.id)

    assert loaded.score == Decimal("0.00")
    assert loaded.scoring_version == "1.0"


def test_incomplete_scan_preserves_findings_without_zero_score(aggregation_database) -> None:
    engine, api_id, endpoint_id = aggregation_database
    from app.scan_runner import _finalize_scan

    with Session(engine) as db:
        scan = _new_scan(
            db,
            api_id,
            [{"detector": "bola", "status": "executed"}, {"detector": "bfla", "status": "skipped"}],
        )
        _add_finding(db, scan.id, endpoint_id, "85.5", "high")
        db.commit()
        _finalize_scan(db, scan.id, "completed")
        loaded = db.get(Scan, scan.id)
        finding_count = db.query(Finding).filter_by(scan_id=scan.id).count()

    assert loaded.assessment_status == "incomplete"
    assert loaded.score is None
    assert finding_count == 1


def test_scoring_version_mismatch_omits_delta(aggregation_database) -> None:
    engine, api_id, endpoint_id = aggregation_database
    from app.scan_runner import _finalize_scan

    with Session(engine) as db:
        previous = _new_scan(
            db,
            api_id,
            [
                {"detector": "bola", "status": "executed"},
                {"detector": "bfla", "status": "executed"},
            ],
            status="completed",
        )
        previous.score = Decimal("40.0")
        previous.scoring_version = "0.9"
        previous.completed_at = datetime.now(UTC)
        current = _new_scan(
            db,
            api_id,
            [
                {"detector": "bola", "status": "executed"},
                {"detector": "bfla", "status": "executed"},
            ],
        )
        _add_finding(db, current.id, endpoint_id, "86.0", "high")
        db.commit()
        _finalize_scan(db, current.id, "completed")
        history = db.query(ScanHistory).filter_by(scan_id=current.id).one()

    assert history.previous_score == Decimal("40.00")
    assert history.current_score == Decimal("86.00")
    assert history.delta is None
