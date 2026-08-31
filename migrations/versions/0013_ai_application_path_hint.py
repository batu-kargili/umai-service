"""Add path_hint to ai_applications for disambiguating shared-basename apps.

Revision ID: 0013_ai_application_path_hint
Revises: 0012_ai_applications_sessions
Create Date: 2026-07-04 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0013_ai_application_path_hint"
down_revision = "0012_ai_applications_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_applications",
        sa.Column("path_hint", sa.String(length=128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("ai_applications", "path_hint")
