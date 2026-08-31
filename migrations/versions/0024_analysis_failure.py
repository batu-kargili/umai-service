"""Somewhere for an analysis that did not finish to land.

Today any triage verdict other than `suspicious` becomes `triage_benign`, so a
session whose analysis timed out or ran out of budget is recorded as cleared.
That is the worst possible default: the queue looks clean because the work
never happened.

`analysis_error` holds why, and the status vocabulary gains `analysis_failed`.
`analysis_attempts` makes a session that keeps failing visible instead of it
cycling forever through claim and lease expiry.

Revision ID: 0024_analysis_failure
Revises: 0023_transcript_lifecycle
Create Date: 2026-08-31 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0024_analysis_failure"
down_revision = "0023_transcript_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_sessions", sa.Column("analysis_error", sa.UnicodeText(), nullable=True))
    op.add_column(
        "ai_sessions",
        sa.Column(
            "analysis_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
    )
    # Finding the sessions nobody analysed is the reason this exists.
    op.create_index(
        "ix_ai_sessions_analysis_status",
        "ai_sessions",
        ["tenant_id", "analysis_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_ai_sessions_analysis_status", table_name="ai_sessions")
    op.drop_column("ai_sessions", "analysis_attempts")
    op.drop_column("ai_sessions", "analysis_error")
