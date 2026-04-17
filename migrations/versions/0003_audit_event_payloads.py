"""Add payload fields to audit events.

Revision ID: 0003_audit_event_payloads
Revises: 0002_policies
Create Date: 2026-01-05 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0003_audit_event_payloads"
down_revision = "0002_policies"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_events",
        sa.Column("decision_severity", sa.String(length=16), nullable=True),
    )
    op.add_column(
        "audit_events",
        sa.Column("decision_reason", sa.UnicodeText(), nullable=True),
    )
    op.add_column(
        "audit_events",
        sa.Column("latency_ms", sa.Float(), nullable=True),
    )
    op.add_column(
        "audit_events",
        sa.Column("conversation_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "audit_events",
        sa.Column("message", sa.UnicodeText(), nullable=True),
    )
    op.add_column(
        "audit_events",
        sa.Column("request_payload_json", sa.UnicodeText(), nullable=True),
    )
    op.add_column(
        "audit_events",
        sa.Column("response_payload_json", sa.UnicodeText(), nullable=True),
    )
    op.add_column(
        "audit_events",
        sa.Column("triggering_policy_json", sa.UnicodeText(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("audit_events", "triggering_policy_json")
    op.drop_column("audit_events", "response_payload_json")
    op.drop_column("audit_events", "request_payload_json")
    op.drop_column("audit_events", "message")
    op.drop_column("audit_events", "conversation_id")
    op.drop_column("audit_events", "latency_ms")
    op.drop_column("audit_events", "decision_reason")
    op.drop_column("audit_events", "decision_severity")
