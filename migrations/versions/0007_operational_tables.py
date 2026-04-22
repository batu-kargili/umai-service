"""Add operational governance tables.

Revision ID: 0007_operational_tables
Revises: 0006_policy_scope
Create Date: 2026-04-21 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0007_operational_tables"
down_revision = "0006_policy_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "browser_extension_events",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("site", sa.String(length=32), nullable=False),
        sa.Column("url", sa.UnicodeText(), nullable=False),
        sa.Column("tab_id", sa.Integer(), nullable=True),
        sa.Column("user_email", sa.String(length=320), nullable=True),
        sa.Column("user_idp_subject", sa.String(length=128), nullable=True),
        sa.Column("device_id", sa.String(length=128), nullable=False),
        sa.Column("browser_profile_id", sa.String(length=128), nullable=True),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prev_event_hash", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("chain_valid", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("chain_error", sa.UnicodeText(), nullable=True),
        sa.Column("decision", sa.String(length=32), nullable=True),
        sa.Column("message", sa.UnicodeText(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=True),
        sa.Column("prompt_hash", sa.String(length=64), nullable=True),
        sa.Column("response_hash", sa.String(length=64), nullable=True),
        sa.Column("prompt_len", sa.Integer(), nullable=True),
        sa.Column("response_len", sa.Integer(), nullable=True),
        sa.Column("payload_json", sa.UnicodeText(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    op.create_table(
        "evidence_packs",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=True),
        sa.Column("project_id", sa.String(length=64), nullable=True),
        sa.Column("regime", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default=sa.text("'READY'")),
        sa.Column("timeframe_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timeframe_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("artifact_json", sa.UnicodeText(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    op.create_table(
        "approval_requests",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("guardrail_id", sa.String(length=64), nullable=False),
        sa.Column("guardrail_version", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("phase", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default=sa.text("'PENDING'")),
        sa.Column("reason", sa.UnicodeText(), nullable=True),
        sa.Column("resolved_by", sa.String(length=128), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    op.create_table(
        "guardrail_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("guardrail_id", sa.String(length=64), nullable=False),
        sa.Column("guardrail_version", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("phase", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default=sa.text("'QUEUED'")),
        sa.Column("conversation_id", sa.String(length=128), nullable=True),
        sa.Column("request_payload_json", sa.UnicodeText(), nullable=False),
        sa.Column("response_payload_json", sa.UnicodeText(), nullable=True),
        sa.Column("webhook_url", sa.String(length=500), nullable=True),
        sa.Column("webhook_secret", sa.String(length=256), nullable=True),
        sa.Column("error_message", sa.UnicodeText(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "guardrail_publish_gates",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("environment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("project_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("guardrail_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("min_expected_action_accuracy", sa.Float(), nullable=True),
        sa.Column("min_expected_allowed_accuracy", sa.Float(), nullable=True),
        sa.Column("min_eval_cases", sa.Integer(), nullable=False, server_default=sa.text("10")),
        sa.Column("max_p95_latency_ms", sa.Float(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    op.create_table(
        "model_registry_entries",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("environment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("project_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("model_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("model_type", sa.String(length=32), nullable=False),
        sa.Column("owner", sa.String(length=128), nullable=True),
        sa.Column("risk_tier", sa.String(length=16), nullable=False, server_default=sa.text("'MEDIUM'")),
        sa.Column("status", sa.String(length=16), nullable=False, server_default=sa.text("'ACTIVE'")),
        sa.Column("metadata_json", sa.UnicodeText(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "agent_registry_entries",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("environment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("project_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("agent_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("runtime", sa.String(length=64), nullable=False),
        sa.Column("owner", sa.String(length=128), nullable=True),
        sa.Column("risk_tier", sa.String(length=16), nullable=False, server_default=sa.text("'MEDIUM'")),
        sa.Column("status", sa.String(length=16), nullable=False, server_default=sa.text("'ACTIVE'")),
        sa.Column("metadata_json", sa.UnicodeText(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("agent_registry_entries")
    op.drop_table("model_registry_entries")
    op.drop_table("guardrail_publish_gates")
    op.drop_table("guardrail_jobs")
    op.drop_table("approval_requests")
    op.drop_table("evidence_packs")
    op.drop_table("browser_extension_events")
