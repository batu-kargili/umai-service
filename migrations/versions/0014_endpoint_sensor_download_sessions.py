"""Add endpoint sensor download session tracking.

Revision ID: 0014_endpoint_sensor_download_sessions
Revises: 0013_ai_application_path_hint
Create Date: 2026-07-05 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0014_endpoint_sensor_download_sessions"
down_revision = "0013_ai_application_path_hint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "endpoint_sensor_download_sessions",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("employee_idp_subject", sa.String(length=256), nullable=False),
        sa.Column("employee_upn", sa.String(length=320), nullable=True),
        sa.Column("employee_display_name", sa.String(length=200), nullable=True),
        sa.Column("created_ip", sa.String(length=64), nullable=True),
        sa.Column("installer_version", sa.String(length=64), nullable=True),
        sa.Column("bootstrap_token_id", sa.Uuid(), nullable=True),
        sa.Column("bootstrap_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("artifact_id", sa.String(length=128), nullable=True),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=True),
        sa.Column("artifact_filename", sa.String(length=260), nullable=True),
        sa.Column("artifact_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("downloaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("device_id", sa.String(length=128), nullable=True),
        sa.Column("first_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("identity_status", sa.String(length=64), nullable=True),
        sa.Column("failure_reason", sa.UnicodeText(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'requested'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_endpoint_sensor_download_sessions_tenant_status",
        "endpoint_sensor_download_sessions",
        ["tenant_id", "status"],
    )
    op.create_index(
        "ix_endpoint_sensor_download_sessions_tenant_employee",
        "endpoint_sensor_download_sessions",
        ["tenant_id", "employee_upn"],
    )
    op.create_index(
        "ix_endpoint_sensor_download_sessions_tenant_device",
        "endpoint_sensor_download_sessions",
        ["tenant_id", "device_id"],
    )
    op.create_index(
        "ix_endpoint_sensor_download_sessions_bootstrap",
        "endpoint_sensor_download_sessions",
        ["tenant_id", "bootstrap_token_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_endpoint_sensor_download_sessions_bootstrap",
        table_name="endpoint_sensor_download_sessions",
    )
    op.drop_index(
        "ix_endpoint_sensor_download_sessions_tenant_device",
        table_name="endpoint_sensor_download_sessions",
    )
    op.drop_index(
        "ix_endpoint_sensor_download_sessions_tenant_employee",
        table_name="endpoint_sensor_download_sessions",
    )
    op.drop_index(
        "ix_endpoint_sensor_download_sessions_tenant_status",
        table_name="endpoint_sensor_download_sessions",
    )
    op.drop_table("endpoint_sensor_download_sessions")
