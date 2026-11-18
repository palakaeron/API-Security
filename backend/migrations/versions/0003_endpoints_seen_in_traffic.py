"""Add seen_in_traffic flag to endpoints for zombie detection."""

import sqlalchemy as sa
from alembic import op

revision = "0003_endpoints_seen_in_traffic"
down_revision = "0002_discovery_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "endpoints",
        sa.Column(
            "seen_in_traffic",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("endpoints", "seen_in_traffic")
