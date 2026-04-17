"""Initial schema.

Revision ID: 0001_initial
Revises: 
Create Date: 2025-12-27 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=32), server_default=sa.text("'active'"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=True),
        sa.Column("key_hash", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("revoked", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )

    op.create_table(
        "licenses",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("status", sa.String(length=32), server_default=sa.text("'active'"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("features_json", sa.UnicodeText(), nullable=True),
    )

    op.create_table(
        "environments",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("environment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
    )

    op.create_table(
        "projects",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("environment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("project_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
    )

    op.create_table(
        "guardrails",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("environment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("project_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("guardrail_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("current_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("mode", sa.String(length=16), nullable=False),
    )

    op.create_table(
        "guardrail_versions",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("environment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("project_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("guardrail_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("version", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("snapshot_json", sa.UnicodeText(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("guardrail_id", sa.String(length=64), nullable=False),
        sa.Column("guardrail_version", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("phase", sa.String(length=16), nullable=False),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("guardrail_versions")
    op.drop_table("guardrails")
    op.drop_table("projects")
    op.drop_table("environments")
    op.drop_table("licenses")
    op.drop_table("api_keys")
    op.drop_table("tenants")
