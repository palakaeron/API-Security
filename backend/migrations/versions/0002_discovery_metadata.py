"""Add normalized discovery metadata to endpoints."""

import sqlalchemy as sa
from alembic import op

revision = "0002_discovery_metadata"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("parameters", sa.JSON))
    op.add_column("endpoints", sa.Column("request_schema", sa.JSON))
    op.add_column("endpoints", sa.Column("response_schemas", sa.JSON))
    op.add_column(
        "endpoints",
        sa.Column("deprecated", sa.Boolean, nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("endpoints", "deprecated")
    op.drop_column("endpoints", "response_schemas")
    op.drop_column("endpoints", "request_schema")
    op.drop_column("endpoints", "parameters")
