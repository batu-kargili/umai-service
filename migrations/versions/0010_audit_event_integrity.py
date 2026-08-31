"""Add audit event integrity chain columns to audit_events.

Revision ID: 0010_audit_event_integrity
Revises: 0009_endpoint_sensor
Create Date: 2026-06-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_audit_event_integrity"
down_revision = "0009_endpoint_sensor"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("prev_event_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_events", sa.Column("event_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_events", sa.Column("event_signature", sa.String(length=128), nullable=True))
    op.add_column("audit_events", sa.Column("hash_key_id", sa.String(length=64), nullable=True))
    op.add_column(
        "audit_events",
        sa.Column("redacted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )


def downgrade() -> None:
    op.drop_column("audit_events", "redacted")
    op.drop_column("audit_events", "hash_key_id")
    op.drop_column("audit_events", "event_signature")
    op.drop_column("audit_events", "event_hash")
    op.drop_column("audit_events", "prev_event_hash")
