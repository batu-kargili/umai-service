"""add ADR collector device lifecycle audit

Revision ID: 0025_adr_device_audit
Revises: 0024_analysis_failure
"""

from alembic import op
import sqlalchemy as sa


revision = "0025_adr_device_audit"
down_revision = "0024_analysis_failure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "adr_device_audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("actor", sa.String(length=320), nullable=False),
        sa.Column("detail_json", sa.UnicodeText(), nullable=True),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_adr_device_audit_tenant_device_time",
        "adr_device_audit_events",
        ["tenant_id", "device_id", "occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_adr_device_audit_tenant_device_time",
        table_name="adr_device_audit_events",
    )
    op.drop_table("adr_device_audit_events")
