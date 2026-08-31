"""Per-tenant transcript collection mode.

The mode decides what the collector is allowed to send and what the operator
API is allowed to return (contract: transcript-data-modes.md). It belongs to
the tenant, not to a deployment-wide setting: two customers on one platform
make different privacy choices.

Default is `metadata`, not the current behaviour. Today's collector sends full
message content; making that the default for a *new* tenant would opt them
into the most invasive mode without anyone choosing it. Existing tenants keep
what they have by being backfilled to `full_session`.

Revision ID: 0021_tenant_collection_mode
Revises: 0020_outbox_replay_audit
Create Date: 2026-08-31 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0021_tenant_collection_mode"
down_revision = "0020_outbox_replay_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "collection_mode",
            sa.String(length=16),
            server_default=sa.text("'metadata'"),
            nullable=False,
        ),
    )
    # Existing tenants are already collecting full sessions. Silently
    # downgrading them would drop evidence they are relying on; the change of
    # default applies to tenants created from here on.
    op.execute("UPDATE tenants SET collection_mode = 'full_session'")


def downgrade() -> None:
    op.drop_column("tenants", "collection_mode")
