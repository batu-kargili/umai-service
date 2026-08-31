"""Transcript retention and a queryable audit trail for content access.

Two additions:

* `tenants.transcript_retention_days` — transcripts age out separately from
  the sessions and findings that reference them (contract:
  transcript-data-modes.md §7: transcript 30 days, sessions and findings 13
  months). One number per tenant, because retention is a contractual term.
* `transcript_audit_events` — who read a transcript, who deleted one, and why.
  A log line is not evidence anyone can query months later, and "we audit
  access to conversation content" is a claim the product makes.

Revision ID: 0023_transcript_lifecycle
Revises: 0022_transcript_ref_nullable
Create Date: 2026-08-31 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0023_transcript_lifecycle"
down_revision = "0022_transcript_ref_nullable"
branch_labels = None
depends_on = None

DEFAULT_RETENTION_DAYS = 30


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "transcript_retention_days",
            sa.Integer(),
            server_default=sa.text(str(DEFAULT_RETENTION_DAYS)),
            nullable=False,
        ),
    )

    op.create_table(
        "transcript_audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("session_key", sa.String(length=128), nullable=False),
        # `read` | `delete_on_demand` | `delete_retention`
        sa.Column("action", sa.String(length=32), nullable=False),
        # Null for the retention sweep: nobody asked, the clock did.
        sa.Column("actor", sa.String(length=256), nullable=True),
        sa.Column("reason", sa.UnicodeText(), nullable=True),
        sa.Column("transcript_bytes", sa.Integer(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    # The two questions asked of this table: "what happened to this session?"
    # and "what did this tenant do this month?"
    op.create_index(
        "ix_transcript_audit_session",
        "transcript_audit_events",
        ["tenant_id", "session_key", "occurred_at"],
    )
    op.create_index(
        "ix_transcript_audit_recent",
        "transcript_audit_events",
        ["tenant_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_transcript_audit_recent", table_name="transcript_audit_events")
    op.drop_index("ix_transcript_audit_session", table_name="transcript_audit_events")
    op.drop_table("transcript_audit_events")
    op.drop_column("tenants", "transcript_retention_days")
