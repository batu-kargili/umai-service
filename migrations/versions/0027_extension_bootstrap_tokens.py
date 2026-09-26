"""add browser-extension enrollment token ledger

Revision ID: 0027_extension_bootstrap_tokens
Revises: 0026_retire_endpoint_sensor_identity
"""

from alembic import op
import sqlalchemy as sa


revision = "0027_extension_bootstrap_tokens"
down_revision = "0026_retire_endpoint_sensor_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "extension_bootstrap_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=200), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("use_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=320), nullable=True),
        sa.Column("revoke_reason", sa.String(length=500), nullable=True),
        sa.Column("created_by", sa.String(length=320), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("jti", name="uq_extension_bootstrap_tokens_jti"),
    )
    op.create_index(
        "ix_extension_bootstrap_tokens_tenant_created",
        "extension_bootstrap_tokens",
        ["tenant_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_extension_bootstrap_tokens_tenant_created",
        table_name="extension_bootstrap_tokens",
    )
    op.drop_table("extension_bootstrap_tokens")
