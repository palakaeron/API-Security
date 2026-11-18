"""Add database-level scan finding deduplication.

Revision ID: 0007_finding_dedupe_key
Revises: 0006_detector_results
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_finding_dedupe_key"
down_revision = "0006_detector_results"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("dedupe_key", sa.String(length=512), nullable=True))
    connection = op.get_bind()
    duplicate_groups = connection.execute(
        sa.text(
            """
            SELECT scan_id, endpoint_id, category, MIN(id) AS keeper_id
            FROM findings
            WHERE endpoint_id IS NOT NULL
            GROUP BY scan_id, endpoint_id, category
            """
        )
    ).mappings()
    for group in duplicate_groups:
        key = f"{group['scan_id']}:{group['endpoint_id']}:{group['category']}"
        connection.execute(
            sa.text("UPDATE findings SET dedupe_key = :key WHERE id = :id"),
            {"key": key, "id": group["keeper_id"]},
        )
    op.create_index(
        "uq_findings_scan_endpoint_category",
        "findings",
        ["dedupe_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_findings_scan_endpoint_category", table_name="findings")
    op.drop_column("findings", "dedupe_key")
