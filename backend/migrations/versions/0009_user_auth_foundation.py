"""Add user authentication timestamp metadata.

Revision ID: 0009_user_auth_foundation
Revises: 0008_issue_level_risk_fields
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_user_auth_foundation"
down_revision = "0008_issue_level_risk_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # SQLite does not permit ALTER TABLE ADD COLUMN with a non-constant
    # default. Batch recreation preserves existing rows safely.
    with op.batch_alter_table("users", recreate="always") as batch:
        batch.add_column(
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("users", recreate="always") as batch:
        batch.drop_column("updated_at")
