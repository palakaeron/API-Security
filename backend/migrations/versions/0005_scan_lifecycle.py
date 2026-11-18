"""Add scan lifecycle metadata and requested statuses.

Revision ID: 0005_scan_lifecycle
Revises: 0004_api_metadata
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_scan_lifecycle"
down_revision = "0004_api_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scans", recreate="always") as batch:
        batch.alter_column("started_at", nullable=True)
        batch.alter_column("started_at", server_default=None)
        batch.alter_column("status", server_default="pending")
        batch.add_column(
            sa.Column("configuration", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )
        batch.add_column(sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("error_summary", sa.Text(), nullable=True))
        batch.add_column(
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            )
        )
        batch.drop_constraint("ck_scans_status", type_="check")
        batch.create_check_constraint(
            "ck_scans_status",
            "status IN ('pending', 'running', 'completed', 'failed', 'cancelled')",
        )

    op.execute("UPDATE scans SET status = 'pending' WHERE status = 'queued'")
    with op.batch_alter_table("scan_history", recreate="always") as batch:
        batch.add_column(sa.Column("scan_id", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column("status", sa.String(length=32), nullable=False, server_default="pending")
        )
        batch.add_column(
            sa.Column("event", sa.String(length=64), nullable=False, server_default="created")
        )
        batch.alter_column("current_score", nullable=True)
        batch.alter_column("delta", nullable=True)
        batch.create_foreign_key(
            "fk_scan_history_scan_id_scans", "scans", ["scan_id"], ["id"], ondelete="CASCADE"
        )


def downgrade() -> None:
    with op.batch_alter_table("scan_history", recreate="always") as batch:
        batch.drop_constraint("fk_scan_history_scan_id_scans", type_="foreignkey")
        batch.drop_column("event")
        batch.drop_column("status")
        batch.drop_column("scan_id")
        batch.alter_column("current_score", nullable=False)
        batch.alter_column("delta", nullable=False)

    with op.batch_alter_table("scans", recreate="always") as batch:
        batch.drop_constraint("ck_scans_status", type_="check")
        batch.create_check_constraint(
            "ck_scans_status", "status IN ('queued', 'running', 'completed', 'failed')"
        )
        batch.drop_column("created_at")
        batch.drop_column("error_summary")
        batch.drop_column("completed_at")
        batch.drop_column("configuration")
        batch.alter_column("started_at", nullable=False)
        batch.alter_column("status", server_default="queued")
