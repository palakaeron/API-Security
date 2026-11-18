"""Create the Milestone 1 platform schema.

Revision ID: 0001_initial_schema
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("role", sa.String(32), nullable=False, server_default="viewer"),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint("role IN ('viewer', 'analyst', 'admin')", name="ck_users_role"),
    )
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("plan", sa.String(32), nullable=False, server_default="local"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column(
            "owner_id",
            sa.Integer,
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer, sa.ForeignKey("organizations.id", ondelete="SET NULL")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_table(
        "apis",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "project_id",
            sa.Integer,
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("version", sa.String(64)),
        sa.Column("spec_location", sa.String(500)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_table(
        "endpoints",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "api_id", sa.Integer, sa.ForeignKey("apis.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("auth_scheme", sa.String(100)),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint("source IN ('spec', 'postman', 'traffic')", name="ck_endpoints_source"),
        sa.UniqueConstraint("api_id", "path", "method", name="uq_endpoints_api_path_method"),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "api_id", sa.Integer, sa.ForeignKey("apis.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("score", sa.Numeric(5, 2)),
        sa.Column("job_id", sa.String(255)),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')", name="ck_scans_status"
        ),
        sa.CheckConstraint("score IS NULL OR (score >= 0 AND score <= 100)", name="ck_scans_score"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "scan_id", sa.Integer, sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("endpoint_id", sa.Integer, sa.ForeignKey("endpoints.id", ondelete="SET NULL")),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Numeric(5, 2), nullable=False),
        sa.Column("risk_score", sa.Numeric(5, 2)),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')", name="ck_findings_severity"
        ),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 100", name="ck_findings_confidence"),
        sa.CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
            name="ck_findings_risk_score",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'confirmed', 'resolved', 'false_positive')",
            name="ck_findings_status",
        ),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "finding_id",
            sa.Integer,
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("request", sa.JSON, nullable=False),
        sa.Column("response", sa.JSON, nullable=False),
        sa.Column("context", sa.JSON, nullable=False),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_table(
        "remediation",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "finding_id",
            sa.Integer,
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("recommendation", sa.Text, nullable=False),
        sa.Column("verification_status", sa.String(32), nullable=False, server_default="pending"),
        sa.CheckConstraint(
            "verification_status IN ('pending', 'verified', 'failed')", name="ck_remediation_status"
        ),
    )
    op.create_table(
        "scan_history",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "api_id", sa.Integer, sa.ForeignKey("apis.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("previous_score", sa.Numeric(5, 2)),
        sa.Column("current_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("delta", sa.Numeric(6, 2), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "finding_id",
            sa.Integer,
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(32), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
    )

    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_severity_status", "findings", ["severity", "status"])
    op.create_index("ix_evidence_finding_id", "evidence", ["finding_id"])
    op.create_index("ix_scans_api_id_started_at", "scans", ["api_id", "started_at"])


def downgrade() -> None:
    for table in [
        "alerts",
        "scan_history",
        "remediation",
        "evidence",
        "findings",
        "scans",
        "endpoints",
        "apis",
        "projects",
        "organizations",
        "users",
    ]:
        op.drop_table(table)
