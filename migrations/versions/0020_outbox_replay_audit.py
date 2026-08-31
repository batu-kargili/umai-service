"""Record who replayed a dead-lettered delivery.

Replay is an operator action on a security event that failed to reach the SOC.
A log line is not an audit trail — the row itself has to say who put it back.

Revision ID: 0020_outbox_replay_audit
Revises: 0019_siem_outbox
Create Date: 2026-08-31 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0020_outbox_replay_audit"
down_revision = "0019_siem_outbox"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("siem_outbox", sa.Column("replayed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("siem_outbox", sa.Column("replayed_by", sa.String(length=320), nullable=True))


def downgrade() -> None:
    op.drop_column("siem_outbox", "replayed_by")
    op.drop_column("siem_outbox", "replayed_at")
