from decimal import Decimal
from unittest.mock import Mock

from app import scan_runner
from app.database import SQLITE_BUSY_TIMEOUT_MS, Base, get_engine
from app.models import (
    Alert,
    Api,
    Endpoint,
    Evidence,
    Finding,
    Organization,
    Project,
    Remediation,
    Scan,
    ScanHistory,
    User,
)
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session


def test_sqlite_claim_lock_retry_is_bounded(monkeypatch) -> None:
    db = Mock()
    db.get_bind.return_value.dialect.name = "sqlite"
    lock_error = OperationalError("UPDATE scans", {}, Exception("database is locked"))
    successful_result = Mock(rowcount=1)
    db.execute.side_effect = [lock_error, lock_error, successful_result]
    monkeypatch.setattr(scan_runner, "sleep", lambda _delay: None)

    result = scan_runner._execute_claim_update(db, object())

    assert result is successful_result
    assert db.execute.call_count == 3
    assert db.rollback.call_count == 2


def test_non_lock_database_errors_are_not_retried() -> None:
    db = Mock()
    db.get_bind.return_value.dialect.name = "sqlite"
    error = OperationalError("UPDATE scans", {}, Exception("database is corrupt"))
    db.execute.side_effect = error

    try:
        scan_runner._execute_claim_update(db, object())
    except OperationalError as raised:
        assert raised is error
    else:
        raise AssertionError("non-lock database errors must be propagated")

    assert db.execute.call_count == 1


def test_sqlite_busy_timeout_is_configured(tmp_path) -> None:
    engine = get_engine(f"sqlite:///{tmp_path / 'busy-timeout.db'}")

    with engine.connect() as connection:
        timeout = connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one()

    assert timeout == SQLITE_BUSY_TIMEOUT_MS


def test_platform_relationships_round_trip_in_sqlite() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        user = User(email="analyst@example.test", password_hash="synthetic-hash")
        organization = Organization(name="Synthetic Organization")
        project = Project(name="Synthetic Project", owner=user, organization=organization)
        api = Api(name="Synthetic API", project=project, version="1.0")
        endpoint = Endpoint(
            api=api,
            path="/users/{user_id}",
            method="GET",
            source="spec",
            auth_scheme="bearer_jwt",
        )
        scan = Scan(api=api, status="completed")
        finding = Finding(
            scan=scan,
            endpoint=endpoint,
            category="API1:2023 Broken Object Level Authorization",
            severity="high",
            confidence=Decimal("95.00"),
        )
        evidence = Evidence(
            finding=finding,
            request={"method": "GET"},
            response={"status": 200},
            context={"synthetic": True},
        )
        remediation = Remediation(finding=finding, recommendation="Enforce ownership checks.")
        alert = Alert(finding=finding, channel="local")
        history = ScanHistory(
            api=api,
            previous_score=Decimal("80.00"),
            current_score=Decimal("60.00"),
            delta=Decimal("-20.00"),
        )

        session.add_all(
            [project, api, endpoint, scan, finding, evidence, remediation, alert, history]
        )
        session.commit()
        project_id = project.id
        finding_id = finding.id

    with Session(engine) as session:
        loaded_project = session.get(Project, project_id)
        loaded_finding = session.get(Finding, finding_id)

        assert loaded_project is not None
        assert loaded_project.owner.email == "analyst@example.test"
        assert loaded_project.apis[0].endpoints[0].path == "/users/{user_id}"
        assert loaded_project.apis[0].scans[0].findings[0] is loaded_finding
        assert loaded_finding is not None
        assert loaded_finding.evidence[0].context == {"synthetic": True}
        assert loaded_finding.remediation[0].verification_status == "pending"
        assert loaded_finding.alerts[0].status == "pending"
