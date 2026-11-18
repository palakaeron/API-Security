"""Persist sanitized detector execution outcomes.

Revision ID: 0006_detector_results
Revises: 0005_scan_lifecycle
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_detector_results"
down_revision = "0005_scan_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("detector_results", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )


def downgrade() -> None:
    op.drop_column("scans", "detector_results")
