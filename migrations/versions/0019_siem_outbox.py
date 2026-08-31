"""Durable outbox for SIEM delivery.

Findings are what a SOC works from. Delivering them fire-and-forget means a
QRadar restart, a network blip or a cert rotation silently drops security
findings, and nobody finds out — the code said as much in a comment.

The outbox row is written in the same transaction as the finding, so a
delivery can never be lost by a crash between "finding committed" and "event
sent". Draining is UMA-55.

Revision ID: 0019_siem_outbox
Revises: 0018_finding_lifecycle
Create Date: 2026-08-31 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0019_siem_outbox"
down_revision = "0018_finding_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "siem_outbox",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        # Producer's identity for this event — the finding key today. Paired
        # with the schema it makes enqueueing idempotent.
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("event_schema", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.UnicodeText(), nullable=False),
        sa.Column("status", sa.String(length=16), server_default=sa.text("'pending'"), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("last_error", sa.UnicodeText(), nullable=True),
        # When the drain may next try. Backoff is expressed here rather than
        # slept on, so a restart resumes the schedule instead of resetting it.
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        # Re-analysis re-raises the same finding; it must not re-page the SOC
        # by queueing a second copy.
        sa.UniqueConstraint(
            "tenant_id", "event_id", "event_schema", name="uq_siem_outbox_event"
        ),
    )

    # The drain's own query: what is due, oldest first.
    op.create_index(
        "ix_siem_outbox_status_next_attempt",
        "siem_outbox",
        ["status", "next_attempt_at"],
    )
    # "Did this finding reach QRadar?" from the finding detail view.
    op.create_index(
        "ix_siem_outbox_tenant_event", "siem_outbox", ["tenant_id", "event_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_siem_outbox_tenant_event", table_name="siem_outbox")
    op.drop_index("ix_siem_outbox_status_next_attempt", table_name="siem_outbox")
    op.drop_table("siem_outbox")
