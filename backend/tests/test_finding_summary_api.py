from __future__ import annotations

from decimal import Decimal

import pytest
from app.database import Base, get_db, get_engine
from app.main import app
from app.models import Api, Endpoint, Evidence, Finding, Project, Scan, User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture
def findings_client(tmp_path):
    engine = get_engine(f"sqlite:///{tmp_path / 'finding-api.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(User(id=1, email="findings-owner@example.test", password_hash="hash"))
        db.commit()

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        yield TestClient(app), engine
    finally:
        app.dependency_overrides.pop(get_db, None)


def _scan(engine, *, incomplete: bool = False) -> tuple[int, int, int]:
    with Session(engine) as db:
        project = Project(name="Summary project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="Summary API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        read_endpoint = Endpoint(api_id=api.id, path="/users/2", method="GET", source="spec")
        db.add(read_endpoint)
        db.flush()
        scan = Scan(
            api_id=api.id,
            status="completed",
            configuration={"detectors": ["bola", "misconfiguration"]},
            detector_results=(
                [
                    {"detector": "bola", "status": "executed"},
                    {"detector": "misconfiguration", "status": "skipped"},
                ]
                if incomplete
                else [
                    {"detector": "bola", "status": "executed"},
                    {"detector": "misconfiguration", "status": "executed"},
                ]
            ),
            score=None if incomplete else Decimal("80.0"),
            scoring_version=None if incomplete else "1.0",
            assessment_status="incomplete" if incomplete else "complete",
        )
        db.add(scan)
        db.commit()
        return project.id, api.id, scan.id


def _add_finding(engine, scan_id: int, endpoint_id: int, *, legacy: bool = False) -> int:
    with Session(engine) as db:
        finding = Finding(
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            category="bola",
            severity="high",
            confidence=Decimal("90.00"),
            issue_code=None if legacy else "bola.cross_user_access",
            impact=None if legacy else Decimal("85.00"),
            exploitability=None if legacy else Decimal("80.00"),
            risk_score=None if legacy else Decimal("80.00"),
            risk_severity=None if legacy else "high",
            scoring_version=None if legacy else "1.0",
            finding_identity=None if legacy else f"finding-{scan_id}-{endpoint_id}",
            dedupe_key=f"dedupe-{scan_id}-{endpoint_id}-{legacy}",
        )
        db.add(finding)
        db.flush()
        db.add(
            Evidence(
                finding_id=finding.id,
                request={"headers": {"Authorization": "Bearer secret-token"}},
                response={"body": {"password": "plain-password", "id": 2}},
                context={"token": "jwt.secret.value"},
            )
        )
        db.commit()
        return finding.id


def test_finding_list_and_detail_sanitize_evidence(findings_client) -> None:
    client, engine = findings_client
    _, _, scan_id = _scan(engine)
    with Session(engine) as db:
        endpoint_id = db.query(Endpoint.id).one()[0]
    finding_id = _add_finding(engine, scan_id, endpoint_id)

    listed = client.get(f"/scans/{scan_id}/findings")
    assert listed.status_code == 200
    body = listed.json()
    assert body["total"] == 1
    assert body["items"][0]["issue_code"] == "bola.cross_user_access"
    assert body["items"][0]["endpoint"]["method"] == "GET"
    assert body["items"][0]["evidence"][0]["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert body["items"][0]["evidence"][0]["response"]["body"]["password"] == "[REDACTED]"

    detail = client.get(f"/findings/{finding_id}")
    assert detail.status_code == 200
    assert detail.json()["scan_id"] == scan_id
    assert client.get("/findings/99999").status_code == 404


def test_legacy_finding_keeps_scoring_fields_null(findings_client) -> None:
    client, engine = findings_client
    _, _, scan_id = _scan(engine)
    with Session(engine) as db:
        endpoint_id = db.query(Endpoint.id).one()[0]
    finding_id = _add_finding(engine, scan_id, endpoint_id, legacy=True)

    response = client.get(f"/findings/{finding_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["issue_code"] is None
    assert data["risk_score"] is None
    assert data["risk_severity"] is None
    assert data["scoring_version"] is None


def test_complete_summary_reports_score_counts_and_coverage(findings_client) -> None:
    client, engine = findings_client
    _, _, scan_id = _scan(engine)
    with Session(engine) as db:
        endpoint_id = db.query(Endpoint.id).one()[0]
    _add_finding(engine, scan_id, endpoint_id)

    response = client.get(f"/scans/{scan_id}/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["assessment_status"] == "complete"
    assert data["overall_risk_score"] == 80.0
    assert data["severity_counts"]["high"] == 1
    assert data["configured_detectors"] == 2
    assert data["executed_detectors"] == 2
    assert data["detector_coverage"] == 1.0
    assert data["assessment_complete"] is True


def test_incomplete_summary_preserves_findings_but_not_clean_score(findings_client) -> None:
    client, engine = findings_client
    _, _, scan_id = _scan(engine, incomplete=True)
    with Session(engine) as db:
        endpoint_id = db.query(Endpoint.id).one()[0]
    _add_finding(engine, scan_id, endpoint_id)

    response = client.get(f"/scans/{scan_id}/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 1
    assert data["overall_risk_score"] is None
    assert data["assessment_status"] == "incomplete"
    assert data["skipped_detectors"] == 1
    assert data["detector_coverage"] == 0.5
    assert data["assessment_incomplete"] is True


def test_missing_scan_resources_return_not_found(findings_client) -> None:
    client, _ = findings_client
    assert client.get("/scans/99999/findings").status_code == 404
    assert client.get("/scans/99999/summary").status_code == 404
