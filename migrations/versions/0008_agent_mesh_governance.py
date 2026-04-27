"""Add Agent Mesh governance identity and run tree tables.

Revision ID: 0008_agent_mesh_governance
Revises: 0007_operational_tables
Create Date: 2026-04-26 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0008_agent_mesh_governance"
down_revision = "0007_operational_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("run_id", sa.String(length=64), nullable=True))
    op.add_column("audit_events", sa.Column("step_id", sa.String(length=64), nullable=True))
    op.add_column("audit_events", sa.Column("agent_id", sa.String(length=64), nullable=True))
    op.add_column("audit_events", sa.Column("agent_did", sa.String(length=256), nullable=True))
    op.add_column("audit_events", sa.Column("action_resource_json", sa.UnicodeText(), nullable=True))

    op.add_column("agent_registry_entries", sa.Column("agent_did", sa.String(length=256), nullable=True))
    op.add_column(
        "agent_registry_entries",
        sa.Column("public_key_fingerprint", sa.String(length=128), nullable=True),
    )
    op.add_column("agent_registry_entries", sa.Column("capabilities_json", sa.UnicodeText(), nullable=True))
    op.add_column(
        "agent_registry_entries",
        sa.Column("trust_score", sa.Float(), nullable=False, server_default=sa.text("0.25")),
    )
    op.add_column(
        "agent_registry_entries",
        sa.Column("trust_tier", sa.String(length=24), nullable=False, server_default=sa.text("'SANDBOX'")),
    )
    op.add_column(
        "agent_registry_entries",
        sa.Column(
            "identity_status",
            sa.String(length=24),
            nullable=False,
            server_default=sa.text("'UNREGISTERED'"),
        ),
    )
    op.add_column(
        "agent_registry_entries",
        sa.Column("kill_switch_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column("agent_registry_entries", sa.Column("kill_switch_reason", sa.UnicodeText(), nullable=True))
    op.add_column(
        "agent_registry_entries",
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "agent_identity_bootstrap_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
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
        "ix_agent_identity_bootstrap_tokens_lookup",
        "agent_identity_bootstrap_tokens",
        ["tenant_id", "environment_id", "project_id", "agent_id", "token_hash"],
    )

    op.create_table(
        "agent_identity_credentials",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("agent_did", sa.String(length=256), nullable=False),
        sa.Column("public_key_b64", sa.UnicodeText(), nullable=False),
        sa.Column("public_key_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default=sa.text("'ACTIVE'")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_from_credential_id", sa.Uuid(), nullable=True),
        sa.Column("bootstrap_token_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_agent_identity_credentials_lookup",
        "agent_identity_credentials",
        ["tenant_id", "environment_id", "project_id", "agent_id", "agent_did"],
    )

    op.create_table(
        "agent_identity_nonces",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_agent_identity_nonces_unique",
        "agent_identity_nonces",
        ["tenant_id", "environment_id", "project_id", "agent_id", "nonce"],
        unique=True,
    )

    op.create_table(
        "agent_run_sessions",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("environment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("project_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("run_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("agent_did", sa.String(length=256), nullable=False),
        sa.Column("guardrail_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False, server_default=sa.text("'RUNNING'")),
        sa.Column("decision_action", sa.String(length=32), nullable=True),
        sa.Column("decision_severity", sa.String(length=16), nullable=True),
        sa.Column("trust_score", sa.Float(), nullable=True),
        sa.Column("trust_tier", sa.String(length=24), nullable=True),
        sa.Column("summary_json", sa.UnicodeText(), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "agent_run_steps",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("environment_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("project_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("run_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("step_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("parent_step_id", sa.String(length=64), nullable=True),
        sa.Column("sequence", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("phase", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False, server_default=sa.text("'RECORDED'")),
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("agent_did", sa.String(length=256), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=True),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_name", sa.String(length=256), nullable=True),
        sa.Column("decision_action", sa.String(length=32), nullable=True),
        sa.Column("decision_severity", sa.String(length=16), nullable=True),
        sa.Column("decision_reason", sa.UnicodeText(), nullable=True),
        sa.Column("policy_id", sa.String(length=128), nullable=True),
        sa.Column("matched_rule_id", sa.String(length=128), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("payload_summary", sa.UnicodeText(), nullable=True),
        sa.Column("metadata_json", sa.UnicodeText(), nullable=True),
        sa.Column("input_hash", sa.String(length=64), nullable=True),
        sa.Column("output_hash", sa.String(length=64), nullable=True),
        sa.Column("prev_step_hash", sa.String(length=64), nullable=True),
        sa.Column("step_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_agent_run_steps_run_sequence",
        "agent_run_steps",
        ["tenant_id", "environment_id", "project_id", "run_id", "sequence"],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_run_steps_run_sequence", table_name="agent_run_steps")
    op.drop_table("agent_run_steps")
    op.drop_table("agent_run_sessions")
    op.drop_index("ix_agent_identity_nonces_unique", table_name="agent_identity_nonces")
    op.drop_table("agent_identity_nonces")
    op.drop_index("ix_agent_identity_credentials_lookup", table_name="agent_identity_credentials")
    op.drop_table("agent_identity_credentials")
    op.drop_index(
        "ix_agent_identity_bootstrap_tokens_lookup",
        table_name="agent_identity_bootstrap_tokens",
    )
    op.drop_table("agent_identity_bootstrap_tokens")

    op.drop_column("agent_registry_entries", "last_seen_at")
    op.drop_column("agent_registry_entries", "kill_switch_reason")
    op.drop_column("agent_registry_entries", "kill_switch_enabled")
    op.drop_column("agent_registry_entries", "identity_status")
    op.drop_column("agent_registry_entries", "trust_tier")
    op.drop_column("agent_registry_entries", "trust_score")
    op.drop_column("agent_registry_entries", "capabilities_json")
    op.drop_column("agent_registry_entries", "public_key_fingerprint")
    op.drop_column("agent_registry_entries", "agent_did")

    op.drop_column("audit_events", "action_resource_json")
    op.drop_column("audit_events", "agent_did")
    op.drop_column("audit_events", "agent_id")
    op.drop_column("audit_events", "step_id")
    op.drop_column("audit_events", "run_id")
