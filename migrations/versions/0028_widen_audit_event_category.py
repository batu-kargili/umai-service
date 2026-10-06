"""widen audit_events.category to fit policy category names

Policy categories are defined by the policy library, not by this column, and
four shipped ones are longer than 32 characters:

    SIM_SWAP_OR_NUMBER_PORT_OUT_ABUSE          33
    EXECUTIVE_OR_REGULATOR_IMPERSONATION       36
    LAWFUL_INTERCEPT_OR_SURVEILLANCE_ABUSE     38
    HIGH_RISK_PROFILING_OR_AUTOMATED_DECISION  41

Writing the audit row for a decision in any of them raised
StringDataRightTruncationError, which failed the whole guard request with a
500 -- so the four most serious telecom detections returned no decision at all.

Revision ID: 0028_widen_audit_event_category
Revises: 0027_extension_bootstrap_tokens
"""

from alembic import op
import sqlalchemy as sa


revision = "0028_widen_audit_event_category"
down_revision = "0027_extension_bootstrap_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "audit_events",
        "category",
        existing_type=sa.String(length=32),
        type_=sa.String(length=128),
        existing_nullable=True,
    )


def downgrade() -> None:
    # Rows written since the upgrade may not fit again; truncate to the old
    # width rather than letting the ALTER fail halfway through.
    op.execute("UPDATE audit_events SET category = LEFT(category, 32) WHERE LENGTH(category) > 32")
    op.alter_column(
        "audit_events",
        "category",
        existing_type=sa.String(length=128),
        type_=sa.String(length=32),
        existing_nullable=True,
    )
