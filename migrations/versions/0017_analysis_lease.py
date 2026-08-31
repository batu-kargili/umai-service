"""Add analysis worker lease columns to ai_sessions.

Revision ID: 0017_analysis_lease
Revises: 0016_findings
Create Date: 2026-08-03 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0017_analysis_lease"
down_revision = "0016_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_sessions", sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("ai_sessions", sa.Column("claimed_by", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_sessions", "claimed_by")
    op.drop_column("ai_sessions", "claimed_at")
