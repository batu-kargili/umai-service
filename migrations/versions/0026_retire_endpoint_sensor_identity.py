"""Move active ADR identity tables out of the retired sensor namespace.

Revision ID: 0026_retire_endpoint_sensor_identity
Revises: 0025_adr_device_audit
"""

from alembic import op

revision = "0026_retire_endpoint_sensor_identity"
down_revision = "0025_adr_device_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.rename_table("endpoint_sensor_devices", "adr_devices")
    op.rename_table("endpoint_sensor_bootstrap_tokens", "adr_bootstrap_tokens")
    op.alter_column("ai_applications", "sensor_capture", new_column_name="collector_capture")


def downgrade() -> None:
    op.alter_column("ai_applications", "collector_capture", new_column_name="sensor_capture")
    op.rename_table("adr_bootstrap_tokens", "endpoint_sensor_bootstrap_tokens")
    op.rename_table("adr_devices", "endpoint_sensor_devices")
