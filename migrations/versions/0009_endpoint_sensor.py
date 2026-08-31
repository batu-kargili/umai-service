"""Add endpoint sensor service foundation tables.

Revision ID: 0009_endpoint_sensor
Revises: 0008_agent_mesh_governance
Create Date: 2026-05-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0009_endpoint_sensor"
down_revision = "0008_agent_mesh_governance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "endpoint_sensor_events",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("event_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("process_name", sa.String(length=260), nullable=True),
        sa.Column("process_path", sa.UnicodeText(), nullable=True),
        sa.Column("parent_process", sa.String(length=260), nullable=True),
        sa.Column("destination_host", sa.String(length=255), nullable=True),
        sa.Column("destination_sni", sa.String(length=255), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("user_email", sa.String(length=320), nullable=True),
        sa.Column("user_idp_subject", sa.String(length=128), nullable=True),
        sa.Column("device_id", sa.String(length=128), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prev_event_hash", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("chain_valid", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("chain_error", sa.UnicodeText(), nullable=True),
        sa.Column("decision", sa.String(length=32), nullable=True),
        sa.Column("message", sa.UnicodeText(), nullable=True),
        sa.Column("prompt_hash", sa.String(length=64), nullable=True),
        sa.Column("prompt_len", sa.Integer(), nullable=True),
        sa.Column("dlp_tags_json", sa.UnicodeText(), nullable=True),
        sa.Column("file_context_json", sa.UnicodeText(), nullable=True),
        sa.Column("payload_json", sa.UnicodeText(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_endpoint_sensor_events_tenant_captured",
        "endpoint_sensor_events",
        ["tenant_id", "captured_at"],
    )
    op.create_index(
        "ix_endpoint_sensor_events_tenant_device_captured",
        "endpoint_sensor_events",
        ["tenant_id", "device_id", "captured_at"],
    )
    op.create_index(
        "ix_endpoint_sensor_events_tenant_destination",
        "endpoint_sensor_events",
        ["tenant_id", "destination_host"],
    )
    op.create_index(
        "ix_endpoint_sensor_events_tenant_process",
        "endpoint_sensor_events",
        ["tenant_id", "process_name"],
    )

    op.create_table(
        "endpoint_sensor_devices",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("device_id", sa.String(length=128), primary_key=True, nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("os", sa.String(length=64), nullable=True),
        sa.Column("os_version", sa.String(length=128), nullable=True),
        sa.Column("agent_version", sa.String(length=64), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_policy_etag", sa.String(length=128), nullable=True),
        sa.Column("last_user_email", sa.String(length=320), nullable=True),
        sa.Column("identity_status", sa.String(length=64), nullable=True),
        sa.Column("queue_depth", sa.Integer(), nullable=True),
        sa.Column("last_successful_upload_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.UnicodeText(), nullable=True),
        sa.Column(
            "enrolled_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'active'")),
    )
    op.create_index(
        "ix_endpoint_sensor_devices_tenant_status",
        "endpoint_sensor_devices",
        ["tenant_id", "status"],
    )
    op.create_index(
        "ix_endpoint_sensor_devices_tenant_heartbeat",
        "endpoint_sensor_devices",
        ["tenant_id", "last_heartbeat_at"],
    )

    op.create_table(
        "endpoint_sensor_bootstrap_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("device_id", sa.String(length=128), nullable=True),
        sa.Column("subject", sa.String(length=256), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_endpoint_sensor_bootstrap_tokens_lookup",
        "endpoint_sensor_bootstrap_tokens",
        ["tenant_id", "token_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_endpoint_sensor_bootstrap_tokens_lookup", table_name="endpoint_sensor_bootstrap_tokens")
    op.drop_table("endpoint_sensor_bootstrap_tokens")
    op.drop_index("ix_endpoint_sensor_devices_tenant_heartbeat", table_name="endpoint_sensor_devices")
    op.drop_index("ix_endpoint_sensor_devices_tenant_status", table_name="endpoint_sensor_devices")
    op.drop_table("endpoint_sensor_devices")
    op.drop_index("ix_endpoint_sensor_events_tenant_process", table_name="endpoint_sensor_events")
    op.drop_index("ix_endpoint_sensor_events_tenant_destination", table_name="endpoint_sensor_events")
    op.drop_index("ix_endpoint_sensor_events_tenant_device_captured", table_name="endpoint_sensor_events")
    op.drop_index("ix_endpoint_sensor_events_tenant_captured", table_name="endpoint_sensor_events")
    op.drop_table("endpoint_sensor_events")
