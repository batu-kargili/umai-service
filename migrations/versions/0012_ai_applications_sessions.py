"""Add AI application registry and usage session tables.

Revision ID: 0012_ai_applications_sessions
Revises: 0011_guardrail_version_metadata
Create Date: 2026-07-02 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0012_ai_applications_sessions"
down_revision = "0011_guardrail_version_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_applications",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("vendor", sa.String(length=200), nullable=True),
        sa.Column("category", sa.String(length=32), nullable=False, server_default=sa.text("'other'")),
        sa.Column("risk_level", sa.String(length=16), nullable=False, server_default=sa.text("'none'")),
        sa.Column("icon_key", sa.String(length=64), nullable=True),
        sa.Column("domains_json", sa.UnicodeText(), nullable=False),
        sa.Column("process_names_json", sa.UnicodeText(), nullable=False),
        sa.Column("ports_json", sa.UnicodeText(), nullable=False),
        sa.Column("app_type", sa.String(length=16), nullable=False, server_default=sa.text("'web'")),
        sa.Column("is_sanctioned", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_training", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("sensor_capture", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("inventory_only", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("source", sa.String(length=16), nullable=False, server_default=sa.text("'builtin'")),
        sa.Column("is_customized", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ux_ai_applications_tenant_slug",
        "ai_applications",
        ["tenant_id", "slug"],
        unique=True,
    )

    op.create_table(
        "ai_usage_sessions",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("app_id", sa.Uuid(), nullable=True),
        sa.Column("app_slug", sa.String(length=64), nullable=True),
        sa.Column("user_key", sa.String(length=320), nullable=False),
        sa.Column("device_id", sa.String(length=128), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("session_type", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("dlp_hit_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_ai_usage_sessions_open_lookup",
        "ai_usage_sessions",
        ["tenant_id", "device_id", "app_slug", "session_type", "last_activity_at"],
    )
    op.create_index(
        "ix_ai_usage_sessions_tenant_app_started",
        "ai_usage_sessions",
        ["tenant_id", "app_slug", "started_at"],
    )
    op.create_index(
        "ix_ai_usage_sessions_tenant_started",
        "ai_usage_sessions",
        ["tenant_id", "started_at"],
    )

    op.add_column(
        "endpoint_sensor_events",
        sa.Column("session_id", sa.String(length=36), nullable=True),
    )
    op.create_index(
        "ix_endpoint_sensor_events_tenant_session",
        "endpoint_sensor_events",
        ["tenant_id", "session_id"],
    )
    op.add_column(
        "browser_extension_events",
        sa.Column("session_id", sa.String(length=36), nullable=True),
    )
    op.create_index(
        "ix_browser_extension_events_tenant_session",
        "browser_extension_events",
        ["tenant_id", "session_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_browser_extension_events_tenant_session", table_name="browser_extension_events")
    op.drop_column("browser_extension_events", "session_id")
    op.drop_index("ix_endpoint_sensor_events_tenant_session", table_name="endpoint_sensor_events")
    op.drop_column("endpoint_sensor_events", "session_id")
    op.drop_index("ix_ai_usage_sessions_tenant_started", table_name="ai_usage_sessions")
    op.drop_index("ix_ai_usage_sessions_tenant_app_started", table_name="ai_usage_sessions")
    op.drop_index("ix_ai_usage_sessions_open_lookup", table_name="ai_usage_sessions")
    op.drop_table("ai_usage_sessions")
    op.drop_index("ux_ai_applications_tenant_slug", table_name="ai_applications")
    op.drop_table("ai_applications")
