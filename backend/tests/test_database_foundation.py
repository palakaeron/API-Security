from decimal import Decimal

from app.database import Base
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
from sqlalchemy.orm import Session


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
