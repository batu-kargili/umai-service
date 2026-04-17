"""Add policies table.

Revision ID: 0002_policies
Revises: 0001_initial
Create Date: 2025-12-28 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0002_policies"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("environment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("project_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("policy_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("phases_json", sa.UnicodeText(), nullable=False),
        sa.Column("config_json", sa.UnicodeText(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("policies")
