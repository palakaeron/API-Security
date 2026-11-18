from __future__ import annotations

from threading import Event, Thread
from types import SimpleNamespace

import pytest
from app.database import Base, get_db, get_engine
from app.detectors.base import DetectorResult, OWASPCategory, Severity
from app.detectors.base import Evidence as DetectorEvidence
from app.main import app
from app.models import Api, Endpoint, Evidence, Finding, Project, Scan, ScanHistory, User
from app.routers import scans as scans_router
from app.scan_runner import cancel_scan
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker


@pytest.fixture
def scan_client(tmp_path):
    engine = get_engine(f"sqlite:///{tmp_path / 'scans.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(User(id=1, email="scan-owner@example.test", password_hash="hash"))
        db.commit()

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        yield TestClient(app), engine
    finally:
        app.dependency_overrides.pop(get_db, None)


def _register_api(client: TestClient, base_url: str = "http://127.0.0.1:8101") -> int:
    project = client.post("/projects", json={"name": "Scan project", "owner_id": 1}).json()
    api = client.post(
        f"/projects/{project['id']}/apis",
        json={"name": "Synthetic API", "base_url": base_url},
    ).json()
    return api["id"]


def test_scan_creation_persists_before_scheduling(scan_client, monkeypatch) -> None:
    client, engine = scan_client
    api_id = _register_api(client)
    monkeypatch.setattr(scans_router, "submit_scan", lambda scan_id: True)

    response = client.post(f"/apis/{api_id}/scans", json={})

    assert response.status_code == 202
    scan_id = response.json()["id"]
    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "pending"
        assert scan.configuration == {"detectors": ["misconfiguration"]}


def test_scan_rejects_missing_api_and_unsupported_configuration(scan_client) -> None:
    client, _ = scan_client
    assert client.post("/apis/999/scans", json={}).status_code == 404

    api_id = _register_api(client)
    response = client.post(
        f"/apis/{api_id}/scans", json={"detectors": ["bola"]}
    )
    assert response.status_code == 422


def test_successful_execution_records_history(scan_client, monkeypatch) -> None:
    client, engine = scan_client
    api_id = _register_api(client)
    with Session(engine) as db:
        api = db.get(Api, api_id)
        assert api is not None
        db.add(Endpoint(api=api, path="/health", method="GET", source="spec"))
        scan = Scan(api=api, configuration={"detectors": ["misconfiguration"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id

    result = DetectorResult(
        detector_id="misconfiguration",
        owasp_category=OWASPCategory.MISCONFIGURATION,
        severity=Severity.INFO,
        confidence=0.0,
        vulnerable=True,
        evidence=[
            DetectorEvidence(
                url="http://127.0.0.1:8101/health",
                method="GET",
                request_headers={"Authorization": "Bearer synthetic-token"},
                request_body=None,
                response_status=200,
                response_headers={},
                response_body={"password": "synthetic-password"},
                context={"detector": "misconfiguration"},
            )
        ],
    )
    monkeypatch.setattr(
        "app.scan_runner.MisconfigurationDetector.run", lambda *args, **kwargs: result
    )
    settings = SimpleNamespace(
        database_url="unused",
        controlled_target_hosts="127.0.0.1",
        controlled_target_cidrs="127.0.0.0/8",
    )
    monkeypatch.setattr("app.scan_runner.get_settings", lambda: settings)
    monkeypatch.setattr(
        "app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine)
    )

    from app.scan_runner import run_scan

    run_scan(scan_id)

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        history = db.query(ScanHistory).filter_by(scan_id=scan_id).all()
        finding = db.query(Finding).filter_by(scan_id=scan_id).one()
        evidence = db.query(Evidence).filter_by(finding_id=finding.id).one()
        assert scan is not None and scan.status == "completed"
        assert [item.event for item in history] == ["started", "completed"]
        assert evidence.request["headers"]["Authorization"] == "[REDACTED]"
        assert evidence.response["body"]["password"] == "[REDACTED]"


def test_execution_failure_is_persisted(scan_client, monkeypatch) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="Failure project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="Failure API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        db.add(Endpoint(api=api, path="/health", method="GET", source="spec"))
        scan = Scan(api_id=api.id, configuration={"detectors": ["misconfiguration"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id

    monkeypatch.setattr(
        "app.scan_runner.MisconfigurationDetector.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("synthetic failure")),
    )
    settings = SimpleNamespace(
        database_url="unused",
        controlled_target_hosts="127.0.0.1",
        controlled_target_cidrs="127.0.0.0/8",
    )
    monkeypatch.setattr("app.scan_runner.get_settings", lambda: settings)
    monkeypatch.setattr(
        "app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine)
    )

    from app.scan_runner import run_scan

    run_scan(scan_id)

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.status == "failed"
        assert scan.error_summary == "scan execution failed (RuntimeError)"


def test_running_scan_cancellation_prevents_terminal_overwrite(scan_client, monkeypatch) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="Cancellation project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="Cancellation API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        db.add(Endpoint(api=api, path="/health", method="GET", source="spec"))
        scan = Scan(api_id=api.id, configuration={"detectors": ["misconfiguration"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id

    started = Event()
    release = Event()
    result = DetectorResult(
        detector_id="misconfiguration",
        owasp_category=OWASPCategory.MISCONFIGURATION,
        severity=Severity.INFO,
        confidence=0.0,
        vulnerable=False,
    )

    def blocked_detector(*args, **kwargs):
        started.set()
        assert release.wait(timeout=2)
        return result

    monkeypatch.setattr("app.scan_runner.MisconfigurationDetector.run", blocked_detector)
    settings = SimpleNamespace(
        database_url="unused",
        controlled_target_hosts="127.0.0.1",
        controlled_target_cidrs="127.0.0.0/8",
    )
    monkeypatch.setattr("app.scan_runner.get_settings", lambda: settings)
    monkeypatch.setattr(
        "app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine)
    )

    from app.scan_runner import run_scan

    worker = Thread(target=run_scan, args=(scan_id,))
    worker.start()
    assert started.wait(timeout=2)
    with Session(engine) as db:
        cancel_scan(db, scan_id)
    release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.status == "cancelled"


def test_cancelled_scan_is_not_executed(scan_client) -> None:
    client, engine = scan_client
    api_id = _register_api(client)
    with Session(engine) as db:
        scan = Scan(api_id=api_id, configuration={"detectors": ["misconfiguration"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id
        cancel_scan(db, scan_id)

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.status == "cancelled"
        assert db.query(ScanHistory).filter_by(scan_id=scan_id, event="cancelled").count() == 1


@pytest.mark.parametrize(
    "base_url",
    [
        "https://example.com",
        "http://user:password@127.0.0.1:8101",
        "ftp://127.0.0.1:8101",
    ],
)
def test_scan_rejects_unauthorized_target_before_detector(
    scan_client, monkeypatch, base_url
) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="Target project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="Target API", base_url=base_url)
        db.add(api)
        db.flush()
        scan = Scan(api_id=api.id, configuration={"detectors": ["misconfiguration"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id

    settings = SimpleNamespace(
        database_url="unused",
        controlled_target_hosts="127.0.0.1",
        controlled_target_cidrs="127.0.0.0/8",
    )
    monkeypatch.setattr("app.scan_runner.get_settings", lambda: settings)
    monkeypatch.setattr(
        "app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine)
    )
    monkeypatch.setattr(
        "app.scan_runner.MisconfigurationDetector.run",
        lambda *args, **kwargs: pytest.fail("detector must not run for an unauthorized target"),
    )

    from app.scan_runner import run_scan

    run_scan(scan_id)

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.status == "failed"
        assert scan.error_summary == "scan target is not authorized by the controlled target policy"
