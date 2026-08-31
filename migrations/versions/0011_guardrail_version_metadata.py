"""Add metadata columns to guardrail_versions (signature, key_id, created_by, approved_by, approved_at).

Revision ID: 0011_guardrail_version_metadata
Revises: 0010_audit_event_integrity
Create Date: 2026-06-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0011_guardrail_version_metadata"
down_revision = "0010_audit_event_integrity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("guardrail_versions", sa.Column("signature", sa.String(length=256), nullable=True))
    op.add_column("guardrail_versions", sa.Column("key_id", sa.String(length=64), nullable=True))
    op.add_column("guardrail_versions", sa.Column("created_by", sa.String(length=128), nullable=True))
    op.add_column("guardrail_versions", sa.Column("approved_by", sa.String(length=128), nullable=True))
    op.add_column("guardrail_versions", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("guardrail_versions", "approved_at")
    op.drop_column("guardrail_versions", "approved_by")
    op.drop_column("guardrail_versions", "created_by")
    op.drop_column("guardrail_versions", "key_id")
    op.drop_column("guardrail_versions", "signature")
