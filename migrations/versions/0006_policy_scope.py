"""Add policy scope column.

Revision ID: 0006_policy_scope
Revises: 0005_evaluations
Create Date: 2026-02-02 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0006_policy_scope"
down_revision = "0005_evaluations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "policies",
        sa.Column(
            "scope",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'PROJECT'"),
        ),
    )


def downgrade() -> None:
    op.drop_column("policies", "scope")
