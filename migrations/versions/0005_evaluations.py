"""add evaluations tables

Revision ID: 0005_evaluations
Revises: 0004_merge_api_keys_audit
Create Date: 2026-02-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0005_evaluations"
down_revision = "0004_merge_api_keys_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evaluation_runs",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("guardrail_id", sa.String(length=64), nullable=False),
        sa.Column("guardrail_version", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200)),
        sa.Column("dataset_id", sa.String(length=64)),
        sa.Column("phase", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("total_cases", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("processed_cases", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("metrics_json", sa.UnicodeText()),
        sa.Column("error_message", sa.UnicodeText()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "evaluation_cases",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("guardrail_id", sa.String(length=64), nullable=False),
        sa.Column("guardrail_version", sa.Integer(), nullable=False),
        sa.Column("index", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=128)),
        sa.Column("prompt", sa.UnicodeText(), nullable=False),
        sa.Column("expected_action", sa.String(length=24)),
        sa.Column("expected_allowed", sa.Boolean()),
        sa.Column("expected_severity", sa.String(length=16)),
        sa.Column("decision_action", sa.String(length=24)),
        sa.Column("decision_allowed", sa.Boolean()),
        sa.Column("decision_severity", sa.String(length=16)),
        sa.Column("decision_reason", sa.UnicodeText()),
        sa.Column("triggering_policy_json", sa.UnicodeText()),
        sa.Column("latency_ms", sa.Float()),
        sa.Column("errors_json", sa.UnicodeText()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )


def downgrade() -> None:
    op.drop_table("evaluation_cases")
    op.drop_table("evaluation_runs")
