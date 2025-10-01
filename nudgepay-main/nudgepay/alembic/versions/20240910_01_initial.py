"""Initial schema with core entities."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20240910_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "adminuser",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("totp_secret", sa.String(length=128), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "role",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("'viewer'"),
        ),
        sa.Column(
            "permissions",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column(
            "federated_providers",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "hardware_key_fingerprints",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_adminuser_email", "adminuser", ["email"], unique=True)
    op.create_index("ix_adminuser_is_active", "adminuser", ["is_active"])
    op.create_index("ix_adminuser_role", "adminuser", ["role"])
    op.create_index("ix_adminuser_external_id", "adminuser", ["external_id"], unique=False)

    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("stripe_account_id", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_user_email", "user", ["email"], unique=True)

    op.create_table(
        "client",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], name="fk_client_user_id"),
    )

    op.create_table(
        "invoice",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("number", sa.String(length=255), nullable=False),
        sa.Column("amount_cents", sa.Integer(), nullable=False),
        sa.Column(
            "currency",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'usd'"),
        ),
        sa.Column("due_date", sa.Date(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'Open'"),
        ),
        sa.Column("stripe_payment_link", sa.String(length=512), nullable=True),
        sa.Column("reminders_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.ForeignKeyConstraint(["client_id"], ["client.id"], name="fk_invoice_client_id"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], name="fk_invoice_user_id"),
    )
    op.create_index("ix_invoice_user_id", "invoice", ["user_id"])
    op.create_index("ix_invoice_client_id", "invoice", ["client_id"])

    op.create_table(
        "reminderlog",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("invoice_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.String(length=64), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["invoice_id"], ["invoice.id"], name="fk_reminderlog_invoice_id"),
    )
    op.create_index("ix_reminderlog_invoice_id", "reminderlog", ["invoice_id"])

    op.create_table(
        "adminauditlog",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column(
            "context",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
    op.create_index("ix_adminauditlog_action", "adminauditlog", ["action"])
    op.create_index("ix_adminauditlog_actor", "adminauditlog", ["actor"])
    op.create_index("ix_adminauditlog_created_at", "adminauditlog", ["created_at"])

    op.create_table(
        "processedwebhook",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("provider", sa.String(length=128), nullable=False),
        sa.Column("event_id", sa.String(length=255), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
    )
    op.create_index("ix_processedwebhook_provider", "processedwebhook", ["provider"])
    op.create_index(
        "ix_processedwebhook_event_id",
        "processedwebhook",
        ["event_id"],
        unique=True,
    )

    op.create_table(
        "outboundjob",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_key", sa.String(length=255), nullable=False),
        sa.Column("job_type", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'queued'"),
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_outboundjob_job_key", "outboundjob", ["job_key"], unique=True)
    op.create_index("ix_outboundjob_job_type", "outboundjob", ["job_type"])
    op.create_index("ix_outboundjob_status", "outboundjob", ["status"])
    op.create_index("ix_outboundjob_created_at", "outboundjob", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_outboundjob_created_at", table_name="outboundjob")
    op.drop_index("ix_outboundjob_status", table_name="outboundjob")
    op.drop_index("ix_outboundjob_job_type", table_name="outboundjob")
    op.drop_index("ix_outboundjob_job_key", table_name="outboundjob")
    op.drop_table("outboundjob")

    op.drop_index("ix_processedwebhook_event_id", table_name="processedwebhook")
    op.drop_index("ix_processedwebhook_provider", table_name="processedwebhook")
    op.drop_table("processedwebhook")

    op.drop_index("ix_adminauditlog_created_at", table_name="adminauditlog")
    op.drop_index("ix_adminauditlog_actor", table_name="adminauditlog")
    op.drop_index("ix_adminauditlog_action", table_name="adminauditlog")
    op.drop_table("adminauditlog")

    op.drop_index("ix_reminderlog_invoice_id", table_name="reminderlog")
    op.drop_table("reminderlog")

    op.drop_index("ix_invoice_client_id", table_name="invoice")
    op.drop_index("ix_invoice_user_id", table_name="invoice")
    op.drop_table("invoice")

    op.drop_table("client")

    op.drop_index("ix_user_email", table_name="user")
    op.drop_table("user")

    op.drop_index("ix_adminuser_external_id", table_name="adminuser")
    op.drop_index("ix_adminuser_role", table_name="adminuser")
    op.drop_index("ix_adminuser_is_active", table_name="adminuser")
    op.drop_index("ix_adminuser_email", table_name="adminuser")
    op.drop_table("adminuser")
