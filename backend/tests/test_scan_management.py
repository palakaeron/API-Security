from __future__ import annotations

from threading import Barrier, Event, Thread
from types import SimpleNamespace

import app.scan_runner as scan_runner
import pytest
from app.database import Base, get_db, get_engine
from app.detectors.base import DetectorResult, OWASPCategory, Severity
from app.detectors.base import Evidence as DetectorEvidence
from app.main import app
from app.models import Api, Endpoint, Evidence, Finding, Project, Scan, ScanHistory, User
from app.routers import scans as scans_router
from app.scan_runner import cancel_scan, register_runtime_config
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
    with Session(engine) as db:
        api = db.get(Api, api_id)
        assert api is not None
        db.add(Endpoint(api=api, path="/health", method="GET", source="spec"))
        db.add(Endpoint(api=api, path="/health", method="POST", source="spec"))
        db.commit()
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
        db.add(Endpoint(api=api, path="/health", method="POST", source="spec"))
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
        db.add(Endpoint(api=api, path="/health", method="POST", source="spec"))
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
        db.add(Endpoint(api=api, path="/health", method="POST", source="spec"))
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


@pytest.mark.parametrize(
    ("detector", "class_name", "config", "paths"),
    [
        (
            "bola",
            "BolaDetector",
            {
                "attacker_token": "token",
                "victim_id": "bob",
                "endpoint_path": "/vuln/users/{user_id}",
            },
            ["/vuln/users/{user_id}"],
        ),
        (
            "bfla",
            "BflaDetector",
            {"regular_user_token": "token", "admin_endpoint_path": "/vuln/admin/audit"},
            ["/vuln/admin/audit"],
        ),
        (
            "bopla",
            "BoplaDetector",
            {
                "attacker_token": "token",
                "victim_id": "bob",
                "read_path": "/vuln/profiles/{user_id}",
                "write_path": "/vuln/profiles/{user_id}",
            },
            ["/vuln/profiles/{user_id}"],
        ),
        (
            "broken_auth",
            "BrokenAuthDetector",
            {"valid_token": "token", "endpoint_path": "/vuln/users/{user_id}"},
            ["/vuln/users/{user_id}"],
        ),
        (
            "jwt_analyzer",
            "JwtAnalyzer",
            {
                "username": "alice",
                "password": "synthetic-password",
                "auth_path": "/vuln/auth/token",
                "protected_path": "/vuln/users/{user_id}",
            },
            ["/vuln/users/{user_id}"],
        ),
        ("misconfiguration", "MisconfigurationDetector", {}, ["/health"]),
    ],
)
def test_each_detector_adapter_executes(
    scan_client, monkeypatch, detector, class_name, config, paths
) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name=f"{detector} project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name=f"{detector} API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        for path in paths:
            db.add(Endpoint(api=api, path=path, method="GET", source="spec"))
            if detector == "bopla":
                db.add(Endpoint(api=api, path=path, method="PATCH", source="spec"))
            if detector == "misconfiguration":
                db.add(Endpoint(api=api, path=path, method="POST", source="spec"))
            if detector == "jwt_analyzer":
                db.add(Endpoint(api=api, path="/vuln/auth/token", method="POST", source="spec"))
        scan = Scan(api_id=api.id, configuration={"detectors": [detector]})
        db.add(scan)
        db.commit()
        scan_id = scan.id

    result = DetectorResult(
        detector_id=detector,
        owasp_category=OWASPCategory.MISCONFIGURATION,
        severity=Severity.INFO,
        confidence=0.0,
        vulnerable=False,
    )
    monkeypatch.setattr(f"app.scan_runner.{class_name}.run", lambda *args, **kwargs: result)
    settings = SimpleNamespace(
        database_url="unused",
        controlled_target_hosts="127.0.0.1",
        controlled_target_cidrs="127.0.0.0/8",
    )
    monkeypatch.setattr("app.scan_runner.get_settings", lambda: settings)
    monkeypatch.setattr(
        "app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine)
    )
    register_runtime_config(scan_id, {detector: config})

    from app.scan_runner import run_scan

    run_scan(scan_id)

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.status == "completed"
        assert scan.detector_results[0]["detector"] == detector
        assert scan.detector_results[0]["status"] == "executed"


def test_missing_runtime_prerequisites_are_skipped(scan_client, monkeypatch) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="Skipped project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="Skipped API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        db.add(Endpoint(api=api, path="/vuln/users/{user_id}", method="GET", source="spec"))
        scan = Scan(api_id=api.id, configuration={"detectors": ["bola"]})
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

    from app.scan_runner import run_scan

    run_scan(scan_id)

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.status == "completed"
        assert scan.detector_results == [
            {
                "detector": "bola",
                "status": "skipped",
                "finding_count": 0,
                "reason": "missing prerequisites: attacker_token, victim_id, endpoint_path",
            }
        ]


def test_scan_request_does_not_persist_detector_secrets(scan_client, monkeypatch) -> None:
    client, engine = scan_client
    api_id = _register_api(client)
    with Session(engine) as db:
        api = db.get(Api, api_id)
        assert api is not None
        db.add(Endpoint(api=api, path="/vuln/users/{user_id}", method="GET", source="spec"))
        db.commit()
    monkeypatch.setattr(scans_router, "submit_scan", lambda scan_id: True)
    response = client.post(
        f"/apis/{api_id}/scans",
        json={
            "detectors": ["bola"],
            "detector_config": {
                "bola": {
                    "attacker_token": "raw-secret-token",
                    "victim_id": "bob",
                    "endpoint_path": "/vuln/users/{user_id}",
                }
            },
        },
    )
    assert response.status_code == 202
    assert "raw-secret-token" not in response.text
    scan_id = response.json()["id"]
    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert "raw-secret-token" not in str(scan.configuration)


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


def test_pending_cancellation_removes_runtime_configuration(scan_client) -> None:
    client, engine = scan_client
    api_id = _register_api(client)
    with Session(engine) as db:
        scan = Scan(api_id=api_id, configuration={"detectors": ["bola"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id
        register_runtime_config(scan_id, {"bola": {"attacker_token": "raw-secret"}})
        cancel_scan(db, scan_id)

    assert scan_id not in scan_runner._runtime_configs


def test_executor_submission_failure_removes_runtime_configuration(monkeypatch) -> None:
    scan_id = 999991
    register_runtime_config(scan_id, {"bola": {"attacker_token": "raw-secret"}})

    class FailingExecutor:
        def submit(self, function, scan_id):
            raise RuntimeError("executor unavailable")

    monkeypatch.setattr(scan_runner, "_executor", FailingExecutor())
    with pytest.raises(RuntimeError, match="executor unavailable"):
        scan_runner.submit_scan(scan_id)

    assert scan_id not in scan_runner._runtime_configs


def test_wrong_endpoint_method_is_skipped(scan_client, monkeypatch) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="Method project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="Method API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        db.add(Endpoint(api=api, path="/vuln/users/{user_id}", method="POST", source="spec"))
        scan = Scan(api_id=api.id, configuration={"detectors": ["bola"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id

    settings = SimpleNamespace(
        database_url="unused",
        controlled_target_hosts="127.0.0.1",
        controlled_target_cidrs="127.0.0.0/8",
    )
    monkeypatch.setattr("app.scan_runner.get_settings", lambda: settings)
    monkeypatch.setattr("app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine))
    register_runtime_config(
        scan_id,
        {
            "bola": {
                "attacker_token": "token",
                "victim_id": "bob",
                "endpoint_path": "/vuln/users/{user_id}",
            }
        },
    )

    scan_runner.run_scan(scan_id)

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.detector_results[0]["status"] == "skipped"
        assert "GET" in scan.detector_results[0]["reason"]


def test_jwt_auth_path_must_exist_as_post(scan_client, monkeypatch) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="JWT inventory project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="JWT API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        db.add(Endpoint(api=api, path="/vuln/users/{user_id}", method="GET", source="spec"))
        scan = Scan(api_id=api.id, configuration={"detectors": ["jwt_analyzer"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id

    settings = SimpleNamespace(
        database_url="unused",
        controlled_target_hosts="127.0.0.1",
        controlled_target_cidrs="127.0.0.0/8",
    )
    monkeypatch.setattr("app.scan_runner.get_settings", lambda: settings)
    monkeypatch.setattr("app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine))
    register_runtime_config(
        scan_id,
        {
            "jwt_analyzer": {
                "username": "alice",
                "password": "password",
                "auth_path": "/vuln/auth/token",
                "protected_path": "/vuln/users/{user_id}",
            }
        },
    )

    scan_runner.run_scan(scan_id)

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.detector_results[0]["status"] == "skipped"
        assert "POST" in scan.detector_results[0]["reason"]


def test_graphql_path_must_exist_as_post(scan_client, monkeypatch) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="GraphQL inventory project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="GraphQL API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        db.add(Endpoint(api=api, path="/health", method="GET", source="spec"))
        db.add(Endpoint(api=api, path="/health", method="POST", source="spec"))
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
    monkeypatch.setattr("app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine))
    register_runtime_config(scan_id, {"misconfiguration": {"graphql_path": "/vuln/graphql"}})

    scan_runner.run_scan(scan_id)

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.detector_results[0]["status"] == "skipped"
        assert "/vuln/graphql" in scan.detector_results[0]["reason"]


@pytest.mark.parametrize("field", ["victim_id", "path_param", "protected_path_param"])
def test_unsafe_path_parameters_are_rejected(field) -> None:
    from app.routers.schemas import DetectorConfig
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        DetectorConfig(**{field: "bob?admin=true"})


def test_bopla_findings_use_read_and_write_endpoints(scan_client, monkeypatch) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="BOPLA endpoint project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="BOPLA API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        read_endpoint = Endpoint(
            api=api, path="/vuln/profile/{user_id}", method="GET", source="spec"
        )
        write_endpoint = Endpoint(
            api=api, path="/vuln/profile/{user_id}", method="PATCH", source="spec"
        )
        db.add_all([read_endpoint, write_endpoint])
        scan = Scan(api=api, configuration={"detectors": ["bopla"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id
        read_id, write_id = read_endpoint.id, write_endpoint.id

    result = DetectorResult(
        detector_id="bopla",
        owasp_category=OWASPCategory.BOPLA,
        severity=Severity.CRITICAL,
        confidence=95.0,
        vulnerable=True,
        evidence=[
            DetectorEvidence(
                url="http://127.0.0.1:8101/vuln/profile/bob",
                method="GET",
                request_headers={},
                request_body=None,
                response_status=200,
                response_headers={},
                response_body={"support_pin": "1234"},
                context={"probe": "read", "sensitive_fields_exposed": ["support_pin"]},
            ),
            DetectorEvidence(
                url="http://127.0.0.1:8101/vuln/profile/bob",
                method="PATCH",
                request_headers={},
                request_body={"role": "admin"},
                response_status=200,
                response_headers={},
                response_body={"role": "admin"},
                context={"probe": "write_escalation", "escalation_succeeded": True},
            ),
        ],
    )
    monkeypatch.setattr("app.scan_runner.BoplaDetector.run", lambda *args, **kwargs: result)
    settings = SimpleNamespace(
        database_url="unused",
        controlled_target_hosts="127.0.0.1",
        controlled_target_cidrs="127.0.0.0/8",
    )
    monkeypatch.setattr("app.scan_runner.get_settings", lambda: settings)
    monkeypatch.setattr("app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine))
    register_runtime_config(
        scan_id,
        {
            "bopla": {
                "attacker_token": "token",
                "victim_id": "bob",
                "read_path": "/vuln/profile/{user_id}",
                "write_path": "/vuln/profile/{user_id}",
            }
        },
    )

    scan_runner.run_scan(scan_id)

    with Session(engine) as db:
        findings = db.query(Finding).filter_by(scan_id=scan_id).all()
        assert {finding.endpoint_id for finding in findings} == {read_id, write_id}
        for finding in findings:
            evidence = db.query(Evidence).filter_by(finding_id=finding.id).one()
            if finding.endpoint_id == read_id:
                assert evidence.request["method"] == "GET"
            else:
                assert evidence.request["method"] == "PATCH"


def test_restart_recovery_marks_pending_and_running_scans_failed(scan_client, monkeypatch) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="Recovery project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="Recovery API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        pending = Scan(api=api, status="pending", configuration={"detectors": ["bola"]})
        running = Scan(api=api, status="running", configuration={"detectors": ["bola"]})
        db.add_all([pending, running])
        db.commit()
        pending_id, running_id = pending.id, running.id

    monkeypatch.setattr("app.scan_runner.get_engine", lambda _: engine)
    monkeypatch.setattr("app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine))

    assert scan_runner.reconcile_interrupted_scans() == 2

    with Session(engine) as db:
        recovered = {scan.id: scan for scan in db.query(Scan).all()}
        assert recovered[pending_id].status == "failed"
        assert recovered[running_id].status == "failed"
        assert "runtime configuration was lost" in recovered[pending_id].error_summary
        assert "backend restart" in recovered[running_id].error_summary
        events = {item.event for item in db.query(ScanHistory).all()}
        assert {"recovered_pending", "recovered_running"} <= events


def test_atomic_scan_claim_allows_only_one_worker(scan_client, monkeypatch) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="Claim project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="Claim API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        scan = Scan(api=api, configuration={"detectors": ["misconfiguration"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id

    with Session(engine) as first, Session(engine) as second:
        first_claim = scan_runner._claim_scan(first, scan_id)
        second_claim = scan_runner._claim_scan(second, scan_id)
        assert first_claim is not None
        assert second_claim is None

    with Session(engine) as db:
        assert db.query(ScanHistory).filter_by(scan_id=scan_id, event="started").count() == 1


def test_finding_deduplication_is_database_backed(scan_client) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="Dedupe project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="Dedupe API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        endpoint = Endpoint(api=api, path="/health", method="GET", source="spec")
        first_scan = Scan(api=api, configuration={"detectors": ["bola"]})
        second_scan = Scan(api=api, configuration={"detectors": ["bola"]})
        db.add_all([endpoint, first_scan, second_scan])
        db.flush()
        result = DetectorResult(
            detector_id="bola",
            owasp_category=OWASPCategory.BOLA,
            severity=Severity.HIGH,
            confidence=95.0,
            vulnerable=True,
        )
        assert scan_runner._persist_result(db, first_scan, endpoint, result) == 1
        assert scan_runner._persist_result(db, first_scan, endpoint, result) == 0
        assert scan_runner._persist_result(db, second_scan, endpoint, result) == 1
        db.commit()
        assert db.query(Finding).count() == 2
        assert db.query(Finding).filter_by(dedupe_key=None).count() == 0


def test_concurrent_finding_persistence_keeps_one_row(scan_client) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="Concurrent dedupe project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(project_id=project.id, name="Concurrent API", base_url="http://127.0.0.1:8101")
        db.add(api)
        db.flush()
        endpoint = Endpoint(api=api, path="/health", method="GET", source="spec")
        scan = Scan(api=api, configuration={"detectors": ["bola"]})
        db.add_all([endpoint, scan])
        db.commit()
        scan_id, endpoint_id = scan.id, endpoint.id

    result = DetectorResult(
        detector_id="bola",
        owasp_category=OWASPCategory.BOLA,
        severity=Severity.HIGH,
        confidence=95.0,
        vulnerable=True,
    )
    barrier = Barrier(2)
    counts: list[int] = []

    def persist_from_worker() -> None:
        with Session(engine) as db:
            scan = db.get(Scan, scan_id)
            endpoint = db.get(Endpoint, endpoint_id)
            assert scan is not None and endpoint is not None
            barrier.wait(timeout=3)
            counts.append(scan_runner._persist_result(db, scan, endpoint, result))
            db.commit()

    workers = [Thread(target=persist_from_worker) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
    assert all(not worker.is_alive() for worker in workers)
    assert sorted(counts) == [0, 1]

    with Session(engine) as db:
        assert db.query(Finding).filter_by(scan_id=scan_id).count() == 1


def test_cancellation_between_detector_probes_stops_subsequent_requests(
    scan_client, monkeypatch
) -> None:
    _, engine = scan_client
    with Session(engine) as db:
        project = Project(name="Probe cancellation project", owner_id=1)
        db.add(project)
        db.flush()
        api = Api(
            project_id=project.id,
            name="Probe cancellation API",
            base_url="http://127.0.0.1:8101",
        )
        db.add(api)
        db.flush()
        for path in ("/one", "/two"):
            db.add(Endpoint(api=api, path=path, method="GET", source="spec"))
            db.add(Endpoint(api=api, path=path, method="POST", source="spec"))
        scan = Scan(api=api, configuration={"detectors": ["misconfiguration"]})
        db.add(scan)
        db.commit()
        scan_id = scan.id

    started = Event()
    release = Event()
    calls: list[str] = []

    def first_probe(*args, **kwargs):
        calls.append(kwargs.get("probe_path", ""))
        started.set()
        assert release.wait(timeout=2)
        return DetectorResult(
            detector_id="misconfiguration",
            owasp_category=OWASPCategory.MISCONFIGURATION,
            severity=Severity.INFO,
            confidence=0.0,
            vulnerable=False,
        )

    monkeypatch.setattr("app.scan_runner.MisconfigurationDetector.run", first_probe)
    settings = SimpleNamespace(
        database_url="unused",
        controlled_target_hosts="127.0.0.1",
        controlled_target_cidrs="127.0.0.0/8",
    )
    monkeypatch.setattr("app.scan_runner.get_settings", lambda: settings)
    monkeypatch.setattr("app.scan_runner.get_session_factory", lambda _: sessionmaker(bind=engine))
    register_runtime_config(scan_id, {"misconfiguration": {}})

    worker = Thread(target=scan_runner.run_scan, args=(scan_id,))
    worker.start()
    assert started.wait(timeout=2)
    with Session(engine) as db:
        cancel_scan(db, scan_id)
    release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert calls == ["/one"]
    assert scan_id not in scan_runner._runtime_configs

    with Session(engine) as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.status == "cancelled"
        assert db.query(ScanHistory).filter_by(scan_id=scan_id, event="completed").count() == 0
        assert db.query(ScanHistory).filter_by(scan_id=scan_id, event="failed").count() == 0


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
