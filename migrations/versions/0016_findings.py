"""Add findings raised against agent sessions.

Revision ID: 0016_findings
Revises: 0015_ai_sessions
Create Date: 2026-08-03 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0016_findings"
down_revision = "0015_ai_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("tenant_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("finding_key", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("session_key", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("technique_id", sa.String(length=16), nullable=True),
        sa.Column("technique_name", sa.String(length=128), nullable=True),
        sa.Column("tactic", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.UnicodeText(), nullable=False),
        sa.Column("summary", sa.UnicodeText(), nullable=True),
        sa.Column("evidence_json", sa.UnicodeText(), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=True),
        sa.Column("actor_user", sa.String(length=320), nullable=True),
        sa.Column("actor_device_id", sa.String(length=128), nullable=True),
        sa.Column("project_path", sa.UnicodeText(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detector", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), server_default=sa.text("'open'"), nullable=False),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=True,
        ),
        sa.Column("emitted_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Console list and the SOC morning queue.
    op.create_index(
        "ix_findings_tenant_status_severity",
        "findings",
        ["tenant_id", "status", "severity"],
    )
    # Drill-down from a session to its findings.
    op.create_index("ix_findings_tenant_session", "findings", ["tenant_id", "session_key"])
    # Time-window reporting.
    op.create_index("ix_findings_tenant_detected", "findings", ["tenant_id", "detected_at"])


def downgrade() -> None:
    op.drop_index("ix_findings_tenant_detected", table_name="findings")
    op.drop_index("ix_findings_tenant_session", table_name="findings")
    op.drop_index("ix_findings_tenant_status_severity", table_name="findings")
    op.drop_table("findings")
