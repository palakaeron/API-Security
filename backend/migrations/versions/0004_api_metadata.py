"""Add API registration metadata fields."""

import sqlalchemy as sa
from alembic import op

revision = "0004_api_metadata"
down_revision = "0003_endpoints_seen_in_traffic"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("apis", sa.Column("base_url", sa.String(length=2048), nullable=True))
    op.add_column("apis", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("apis", sa.Column("environment", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("apis", "environment")
    op.drop_column("apis", "description")
    op.drop_column("apis", "base_url")
