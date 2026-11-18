import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from app.database import get_engine
from sqlalchemy import inspect, text


def _alembic_config() -> Config:
    backend_dir = Path(__file__).resolve().parents[1]
    config = Config(str(backend_dir / "alembic.ini"))
    config.set_main_option("script_location", str(backend_dir / "migrations"))
    return config


def test_fresh_migration_has_issue_and_risk_columns(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    command.upgrade(_alembic_config(), "head")

    inspector = inspect(get_engine(database_url))
    finding_columns = {column["name"] for column in inspector.get_columns("findings")}
    scan_columns = {column["name"] for column in inspector.get_columns("scans")}

    assert {
        "issue_code",
        "impact",
        "exploitability",
        "risk_severity",
        "scoring_version",
        "finding_identity",
    } <= finding_columns
    assert {"scoring_version", "assessment_status"} <= scan_columns
    assert "uq_findings_finding_identity" in {
        index["name"] for index in inspector.get_indexes("findings")
    }


def test_upgrade_preserves_legacy_records_and_duplicate_findings(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    config = _alembic_config()
    command.upgrade(config, "0007_finding_dedupe_key")
    engine = get_engine(database_url)

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (id, email, role, password_hash) "
                "VALUES (1, 'legacy@example.test', 'analyst', 'hash')"
            )
        )
        connection.execute(
            text("INSERT INTO projects (id, name, owner_id) VALUES (1, 'Legacy', 1)")
        )
        connection.execute(
            text("INSERT INTO apis (id, project_id, name) VALUES (1, 1, 'Legacy API')")
        )
        connection.execute(
            text(
                "INSERT INTO endpoints (id, api_id, path, method, source) "
                "VALUES (1, 1, '/legacy', 'GET', 'spec')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO scans "
                "(id, api_id, status, configuration, detector_results) "
                "VALUES (1, 1, 'completed', :configuration, :detector_results)"
            ),
            {"configuration": json.dumps({}), "detector_results": json.dumps([])},
        )
        for finding_id in (1, 2):
            connection.execute(
                text(
                    "INSERT INTO findings "
                    "(id, scan_id, endpoint_id, category, severity, confidence, status) "
                    "VALUES (:id, 1, 1, 'API1:2023 Broken Object Level Authorization', "
                    "'high', 95, 'open')"
                ),
                {"id": finding_id},
            )
        connection.execute(
            text("UPDATE findings SET dedupe_key = :key WHERE id = 1"),
            {"key": "1:1:API1:2023 Broken Object Level Authorization"},
        )
        connection.execute(
            text(
                "INSERT INTO evidence "
                "(id, finding_id, request, response, context) "
                "VALUES (1, 1, :request, :response, :context)"
            ),
            {
                "request": json.dumps({"method": "GET"}),
                "response": json.dumps({"status": 200}),
                "context": json.dumps({"legacy": True}),
            },
        )
        connection.execute(
            text(
                "INSERT INTO scan_history "
                "(id, api_id, scan_id, status, event) "
                "VALUES (1, 1, 1, 'completed', 'completed')"
            )
        )

    with engine.connect() as connection:
        legacy_dedupe_key = connection.execute(
            text("SELECT dedupe_key FROM findings WHERE id = 1")
        ).scalar_one()

    command.upgrade(config, "head")

    with engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT id, issue_code, finding_identity, risk_score, scoring_version "
                "FROM findings ORDER BY id"
            )
        ).mappings().all()
        scan = connection.execute(
            text("SELECT scoring_version, assessment_status, score FROM scans WHERE id = 1")
        ).mappings().one()
        evidence_count = connection.execute(text("SELECT COUNT(*) FROM evidence")).scalar_one()
        history_count = connection.execute(text("SELECT COUNT(*) FROM scan_history")).scalar_one()

    assert len(rows) == 2
    assert all(row["issue_code"] == "legacy.detector_result" for row in rows)
    assert rows[0]["finding_identity"] == f"{legacy_dedupe_key}:legacy.detector_result"
    assert rows[1]["finding_identity"] is None
    assert rows[0]["risk_score"] is None
    assert rows[0]["scoring_version"] is None
    assert scan == {"scoring_version": None, "assessment_status": None, "score": None}
    assert evidence_count == 1
    assert history_count == 1
