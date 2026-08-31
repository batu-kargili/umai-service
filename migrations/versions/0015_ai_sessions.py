"""Add ai_sessions, the transcript-level analysis unit.

Revision ID: 0015_ai_sessions
Revises: 0014_endpoint_sensor_download_sessions
Create Date: 2026-08-03 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0015_ai_sessions"
down_revision = "0014_endpoint_sensor_download_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_sessions",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("session_key", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_session_id", sa.String(length=256), nullable=False),
        sa.Column("raw_log_path", sa.UnicodeText(), nullable=True),
        sa.Column("actor_user", sa.String(length=320), nullable=True),
        sa.Column("actor_device_id", sa.String(length=128), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("project_path", sa.UnicodeText(), nullable=True),
        sa.Column("title", sa.UnicodeText(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=True,
        ),
        sa.Column("message_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("tool_call_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("posture_json", sa.UnicodeText(), nullable=True),
        sa.Column("transcript_ref", sa.UnicodeText(), nullable=False),
        sa.Column("transcript_sha256", sa.String(length=64), nullable=False),
        sa.Column("transcript_bytes", sa.Integer(), nullable=True),
        sa.Column("collector_name", sa.String(length=64), nullable=True),
        sa.Column("collector_version", sa.String(length=32), nullable=True),
        sa.Column(
            "analysis_status",
            sa.String(length=24),
            server_default=sa.text("'ingested'"),
            nullable=False,
        ),
        sa.Column("threat_tactic", sa.String(length=64), nullable=True),
        sa.Column("verdict", sa.String(length=24), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=True,
        ),
    )

    # Discover feed and time-window queries.
    op.create_index(
        "ix_ai_sessions_tenant_observed",
        "ai_sessions",
        ["tenant_id", "observed_at"],
    )
    # The analysis pipeline claims work by status.
    op.create_index(
        "ix_ai_sessions_tenant_status",
        "ai_sessions",
        ["tenant_id", "analysis_status"],
    )
    # Per-person drill-down and the identity reconciliation join.
    op.create_index(
        "ix_ai_sessions_tenant_actor",
        "ai_sessions",
        ["tenant_id", "actor_user"],
    )
    # Coverage matrix: which surfaces are actually reporting.
    op.create_index(
        "ix_ai_sessions_tenant_source",
        "ai_sessions",
        ["tenant_id", "source"],
    )


def downgrade() -> None:
    op.drop_index("ix_ai_sessions_tenant_source", table_name="ai_sessions")
    op.drop_index("ix_ai_sessions_tenant_actor", table_name="ai_sessions")
    op.drop_index("ix_ai_sessions_tenant_status", table_name="ai_sessions")
    op.drop_index("ix_ai_sessions_tenant_observed", table_name="ai_sessions")
    op.drop_table("ai_sessions")
