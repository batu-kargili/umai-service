"""Merge api key metadata and audit event payload heads.

Revision ID: 0004_merge_api_keys_audit
Revises: 0003_api_keys_metadata, 0003_audit_event_payloads
Create Date: 2026-01-29 00:00:00.000000
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "0004_merge_api_keys_audit"
down_revision = ("0003_api_keys_metadata", "0003_audit_event_payloads")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
