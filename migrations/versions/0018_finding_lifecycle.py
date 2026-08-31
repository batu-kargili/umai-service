"""Canonical finding fields, lifecycle states and the status audit trail.

Implements the frozen contract in
``docs/contracts/finding-and-worker-result-schema.md`` (platform repo, UMA-40).

Three columns carry the wrong thing today, and this migration corrects the data
as well as the schema:

``tactic``
    The reasoning worker produces an ADR technique id but ships it in
    ``threat_tactic``, and the service writes that straight into ``tactic``
    while hardcoding ``technique_id`` to NULL. So ``tactic`` holds values like
    ``ADR.T0007``. They are moved to ``technique_id``.

``source``
    Written from ``ai_sessions.source``, which is the *AI tool* (``claude``,
    ``cursor``, ``codex``). The contract defines ``source`` as the detection
    *channel* — the axis the finding queue is filtered on. Existing rows all
    came from the ADR channel and are set to ``adr``. The tool name is not
    lost: it stays reachable through ``session_key -> ai_sessions.source``.

``detector``
    The reasoning path writes ``adr``, which is ambiguous — posture findings
    are ADR too, and they write ``posture``. Normalised to ``reasoning``.

Revision ID: 0018_finding_lifecycle
Revises: 0017_analysis_lease
Create Date: 2026-08-31 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0018_finding_lifecycle"
down_revision = "0017_analysis_lease"
branch_labels = None
depends_on = None


# Channels a finding can arrive from. Anything outside this set in an existing
# row is a tool name from the old behaviour and gets normalised to `adr`.
_VALID_SOURCES = ("adr", "extension", "sdk", "red_team", "policy")


def upgrade() -> None:
    # --- new columns, nullable first so the backfill has somewhere to land ---
    op.add_column("findings", sa.Column("category", sa.String(length=48), nullable=True))
    op.add_column("findings", sa.Column("remediation_json", sa.UnicodeText(), nullable=True))
    op.add_column("findings", sa.Column("assignee", sa.String(length=320), nullable=True))

    # --- data corrections -------------------------------------------------
    # Technique ids parked in `tactic`. Only rows that have no technique_id yet
    # are touched, so re-running cannot clobber correctly written data.
    op.execute(
        "UPDATE findings SET technique_id = tactic, tactic = NULL "
        "WHERE technique_id IS NULL AND tactic LIKE 'ADR.T%'"
    )

    # Tool names parked in `source`. Values that are already a valid channel
    # are left alone.
    valid = ", ".join(f"'{s}'" for s in _VALID_SOURCES)
    op.execute(
        f"UPDATE findings SET source = 'adr' "
        f"WHERE source IS NULL OR source NOT IN ({valid})"
    )

    op.execute("UPDATE findings SET detector = 'reasoning' WHERE detector = 'adr'")

    # Historic rows predate categorisation. `other` is a deliberate debt marker:
    # a queue full of `other` means the detectors are not classifying.
    op.execute("UPDATE findings SET category = 'other' WHERE category IS NULL")

    # --- tighten ----------------------------------------------------------
    # batch_alter_table so this works on SQLite too; on PostgreSQL and the
    # other supported engines it emits a plain ALTER.
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("category", existing_type=sa.String(length=48), nullable=False)
        batch.alter_column("source", existing_type=sa.String(length=32), nullable=False)

    # --- lifecycle audit --------------------------------------------------
    # A dedicated table, not `audit_events`: that one is shaped for guardrail
    # decisions and requires environment_id, project_id, guardrail_id,
    # guardrail_version, phase, action and allowed. A finding transition has
    # none of those, and filling them with placeholders would corrupt the
    # audit trail it is supposed to protect.
    op.create_table(
        "finding_status_events",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("finding_key", sa.String(length=64), nullable=False),
        sa.Column("from_status", sa.String(length=16), nullable=True),
        sa.Column("to_status", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=320), nullable=False),
        sa.Column("note", sa.UnicodeText(), nullable=True),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    # The detail view reads one finding's history newest-first.
    op.create_index(
        "ix_finding_status_events_tenant_finding",
        "finding_status_events",
        ["tenant_id", "finding_key", "occurred_at"],
    )

    # Queue filtering by assignee, and "what is on my plate" for an operator.
    op.create_index(
        "ix_findings_tenant_assignee_status",
        "findings",
        ["tenant_id", "assignee", "status"],
    )


def downgrade() -> None:
    """Reverse the schema. The data corrections are NOT reversed.

    Dropping the columns and the audit table restores the previous shape, but
    the technique ids moved out of `tactic`, the normalised `source` values and
    the normalised `detector` values stay corrected. Restoring the old, wrong
    values would mean deliberately re-corrupting the rows.

    Migration class: reversible for schema, restore-required for data
    (see UMA-91).
    """
    op.drop_index("ix_findings_tenant_assignee_status", table_name="findings")
    op.drop_index("ix_finding_status_events_tenant_finding", table_name="finding_status_events")
    op.drop_table("finding_status_events")

    with op.batch_alter_table("findings") as batch:
        batch.alter_column("source", existing_type=sa.String(length=32), nullable=True)

    op.drop_column("findings", "assignee")
    op.drop_column("findings", "remediation_json")
    op.drop_column("findings", "category")
