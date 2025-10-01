"""Add operational support tables."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20240920_02"
down_revision = "20240910_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "secretrotationrunbook",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("spec", sa.String(length=255), nullable=False),
        sa.Column("pattern", sa.String(length=255), nullable=False),
        sa.Column("policy", sa.String(length=255), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hook_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "details",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("dashboard_url", sa.String(length=512), nullable=True),
        sa.Column("runbook_url", sa.String(length=512), nullable=True),
    )
    op.create_index("ix_secretrotationrunbook_spec", "secretrotationrunbook", ["spec"])
    op.create_index("ix_secretrotationrunbook_pattern", "secretrotationrunbook", ["pattern"])
    op.create_index("ix_secretrotationrunbook_policy", "secretrotationrunbook", ["policy"])
    op.create_index("ix_secretrotationrunbook_rotated_at", "secretrotationrunbook", ["rotated_at"])

    op.create_table(
        "delegatedapproval",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column(
            "status",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("required_approvals", sa.Integer(), nullable=False, server_default=sa.text("2")),
        sa.Column(
            "approved_by",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "denied_by",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_delegatedapproval_action", "delegatedapproval", ["action"])
    op.create_index("ix_delegatedapproval_subject", "delegatedapproval", ["subject"])
    op.create_index("ix_delegatedapproval_status", "delegatedapproval", ["status"])
    op.create_index("ix_delegatedapproval_requested_by", "delegatedapproval", ["requested_by"])
    op.create_index("ix_delegatedapproval_created_at", "delegatedapproval", ["created_at"])
    op.create_index("ix_delegatedapproval_updated_at", "delegatedapproval", ["updated_at"])
    op.create_index("ix_delegatedapproval_resolved_at", "delegatedapproval", ["resolved_at"])
    op.create_index("ix_delegatedapproval_expires_at", "delegatedapproval", ["expires_at"])

    op.create_table(
        "servicetoken",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("token_prefix", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "scopes",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
    )
    op.create_index("ix_servicetoken_name", "servicetoken", ["name"])
    op.create_index("ix_servicetoken_token_prefix", "servicetoken", ["token_prefix"])
    op.create_index("ix_servicetoken_token_hash", "servicetoken", ["token_hash"], unique=True)
    op.create_index("ix_servicetoken_created_by", "servicetoken", ["created_by"])
    op.create_index("ix_servicetoken_created_at", "servicetoken", ["created_at"])
    op.create_index("ix_servicetoken_expires_at", "servicetoken", ["expires_at"])
    op.create_index("ix_servicetoken_last_used_at", "servicetoken", ["last_used_at"])
    op.create_index("ix_servicetoken_revoked", "servicetoken", ["revoked"])

    op.create_table(
        "automationexecutionrecord",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.String(length=255), nullable=False),
        sa.Column("job_name", sa.String(length=255), nullable=False),
        sa.Column("scheduler", sa.String(length=255), nullable=True),
        sa.Column("triggered_by", sa.String(length=255), nullable=True),
        sa.Column("ran_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "metrics",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column(
            "details",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
    op.create_index("ix_automationexecutionrecord_run_id", "automationexecutionrecord", ["run_id"], unique=True)
    op.create_index("ix_automationexecutionrecord_job_name", "automationexecutionrecord", ["job_name"])
    op.create_index("ix_automationexecutionrecord_scheduler", "automationexecutionrecord", ["scheduler"])
    op.create_index("ix_automationexecutionrecord_ran_at", "automationexecutionrecord", ["ran_at"])
    op.create_index("ix_automationexecutionrecord_success", "automationexecutionrecord", ["success"])

    op.create_table(
        "deploymentrecord",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("environment", sa.String(length=128), nullable=False),
        sa.Column("build_sha", sa.String(length=255), nullable=False),
        sa.Column("initiated_by", sa.String(length=255), nullable=False),
        sa.Column(
            "status",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("'in_progress'"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_triggered", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "synthetic_gate",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "attributes",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index("ix_deploymentrecord_environment", "deploymentrecord", ["environment"])
    op.create_index("ix_deploymentrecord_build_sha", "deploymentrecord", ["build_sha"])
    op.create_index("ix_deploymentrecord_initiated_by", "deploymentrecord", ["initiated_by"])
    op.create_index("ix_deploymentrecord_status", "deploymentrecord", ["status"])
    op.create_index("ix_deploymentrecord_started_at", "deploymentrecord", ["started_at"])
    op.create_index("ix_deploymentrecord_completed_at", "deploymentrecord", ["completed_at"])
    op.create_index("ix_deploymentrecord_rollback_triggered", "deploymentrecord", ["rollback_triggered"])
    op.create_index("ix_deploymentrecord_synthetic_gate", "deploymentrecord", ["synthetic_gate"])

    op.create_table(
        "incidentevent",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "attributes",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incidentevent_source", "incidentevent", ["source"])
    op.create_index("ix_incidentevent_category", "incidentevent", ["category"])
    op.create_index("ix_incidentevent_severity", "incidentevent", ["severity"])
    op.create_index("ix_incidentevent_created_at", "incidentevent", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_incidentevent_created_at", table_name="incidentevent")
    op.drop_index("ix_incidentevent_severity", table_name="incidentevent")
    op.drop_index("ix_incidentevent_category", table_name="incidentevent")
    op.drop_index("ix_incidentevent_source", table_name="incidentevent")
    op.drop_table("incidentevent")

    op.drop_index("ix_deploymentrecord_synthetic_gate", table_name="deploymentrecord")
    op.drop_index("ix_deploymentrecord_rollback_triggered", table_name="deploymentrecord")
    op.drop_index("ix_deploymentrecord_completed_at", table_name="deploymentrecord")
    op.drop_index("ix_deploymentrecord_started_at", table_name="deploymentrecord")
    op.drop_index("ix_deploymentrecord_status", table_name="deploymentrecord")
    op.drop_index("ix_deploymentrecord_initiated_by", table_name="deploymentrecord")
    op.drop_index("ix_deploymentrecord_build_sha", table_name="deploymentrecord")
    op.drop_index("ix_deploymentrecord_environment", table_name="deploymentrecord")
    op.drop_table("deploymentrecord")

    op.drop_index("ix_automationexecutionrecord_success", table_name="automationexecutionrecord")
    op.drop_index("ix_automationexecutionrecord_ran_at", table_name="automationexecutionrecord")
    op.drop_index("ix_automationexecutionrecord_scheduler", table_name="automationexecutionrecord")
    op.drop_index("ix_automationexecutionrecord_job_name", table_name="automationexecutionrecord")
    op.drop_index("ix_automationexecutionrecord_run_id", table_name="automationexecutionrecord")
    op.drop_table("automationexecutionrecord")

    op.drop_index("ix_servicetoken_revoked", table_name="servicetoken")
    op.drop_index("ix_servicetoken_last_used_at", table_name="servicetoken")
    op.drop_index("ix_servicetoken_expires_at", table_name="servicetoken")
    op.drop_index("ix_servicetoken_created_at", table_name="servicetoken")
    op.drop_index("ix_servicetoken_created_by", table_name="servicetoken")
    op.drop_index("ix_servicetoken_token_hash", table_name="servicetoken")
    op.drop_index("ix_servicetoken_token_prefix", table_name="servicetoken")
    op.drop_index("ix_servicetoken_name", table_name="servicetoken")
    op.drop_table("servicetoken")

    op.drop_index("ix_delegatedapproval_expires_at", table_name="delegatedapproval")
    op.drop_index("ix_delegatedapproval_resolved_at", table_name="delegatedapproval")
    op.drop_index("ix_delegatedapproval_updated_at", table_name="delegatedapproval")
    op.drop_index("ix_delegatedapproval_created_at", table_name="delegatedapproval")
    op.drop_index("ix_delegatedapproval_requested_by", table_name="delegatedapproval")
    op.drop_index("ix_delegatedapproval_status", table_name="delegatedapproval")
    op.drop_index("ix_delegatedapproval_subject", table_name="delegatedapproval")
    op.drop_index("ix_delegatedapproval_action", table_name="delegatedapproval")
    op.drop_table("delegatedapproval")

    op.drop_index("ix_secretrotationrunbook_rotated_at", table_name="secretrotationrunbook")
    op.drop_index("ix_secretrotationrunbook_policy", table_name="secretrotationrunbook")
    op.drop_index("ix_secretrotationrunbook_pattern", table_name="secretrotationrunbook")
    op.drop_index("ix_secretrotationrunbook_spec", table_name="secretrotationrunbook")
    op.drop_table("secretrotationrunbook")
