"""Add nullable issue-level and risk-scoring fields.

Revision ID: 0008_issue_level_risk_fields
Revises: 0007_finding_dedupe_key
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_issue_level_risk_fields"
down_revision = "0007_finding_dedupe_key"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("scoring_version", sa.String(length=16), nullable=True))
    op.add_column("scans", sa.Column("assessment_status", sa.String(length=16), nullable=True))

    op.add_column("findings", sa.Column("issue_code", sa.String(length=128), nullable=True))
    op.add_column("findings", sa.Column("impact", sa.Numeric(5, 2), nullable=True))
    op.add_column("findings", sa.Column("exploitability", sa.Numeric(5, 2), nullable=True))
    op.add_column("findings", sa.Column("risk_severity", sa.String(length=16), nullable=True))
    op.add_column("findings", sa.Column("scoring_version", sa.String(length=16), nullable=True))
    op.add_column(
        "findings", sa.Column("finding_identity", sa.String(length=1024), nullable=True)
    )

    connection = op.get_bind()
    connection.execute(
        sa.text(
            """
            UPDATE findings
            SET issue_code = 'legacy.detector_result'
            WHERE issue_code IS NULL
            """
        )
    )
    # Only rows with an existing unique dedupe_key are safe to normalize.
    # Historical duplicate rows retain NULL finding_identity and remain intact.
    connection.execute(
        sa.text(
            """
            UPDATE findings
            SET finding_identity = dedupe_key || :legacy_suffix
            WHERE dedupe_key IS NOT NULL
            """
        ),
        {"legacy_suffix": ":legacy.detector_result"},
    )
    op.create_index(
        "uq_findings_finding_identity",
        "findings",
        ["finding_identity"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_findings_finding_identity", table_name="findings")
    op.drop_column("findings", "finding_identity")
    op.drop_column("findings", "scoring_version")
    op.drop_column("findings", "risk_severity")
    op.drop_column("findings", "exploitability")
    op.drop_column("findings", "impact")
    op.drop_column("findings", "issue_code")
    op.drop_column("scans", "assessment_status")
    op.drop_column("scans", "scoring_version")
