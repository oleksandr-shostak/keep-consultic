"""Add alert severity proposal knowledge base table

Revision ID: 4c9e1f3ab2d7
Revises: f8a9b2c3d4e5
Create Date: 2026-02-26 12:00:00.000000

"""

import sqlalchemy as sa
import sqlmodel
from alembic import op
from sqlalchemy_utils import UUIDType

# revision identifiers, used by Alembic.
revision = "4c9e1f3ab2d7"
down_revision = "f8a9b2c3d4e5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alertseverityproposal",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("tenant_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("alert_id", UUIDType(binary=False), nullable=False),
        sa.Column(
            "alert_fingerprint", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("source", sa.JSON(), nullable=True),
        sa.Column("provider_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("provider_type", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column(
            "current_severity", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column(
            "proposed_severity", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("reason", sa.TEXT(), nullable=False),
        sa.Column("alert_name", sa.TEXT(), nullable=False),
        sa.Column("alert_message", sa.TEXT(), nullable=True),
        sa.Column("alert_description", sa.TEXT(), nullable=True),
        sa.Column("created_by", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("idempotency_key", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("dedupe_hash", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("sync_status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("sync_status_reason", sa.TEXT(), nullable=True),
        sa.Column("sync_attempts", sa.Integer(), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(), nullable=True),
        sa.Column("openai_file_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("vector_store_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "dedupe_hash",
            name="uq_alertseverityproposal_tenant_dedupe_hash",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_alertseverityproposal_tenant_idempotency_key",
        ),
    )
    op.create_index(
        "ix_alertseverityproposal_alert_fingerprint",
        "alertseverityproposal",
        ["alert_fingerprint"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_created_by",
        "alertseverityproposal",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_current_severity",
        "alertseverityproposal",
        ["current_severity"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_dedupe_hash",
        "alertseverityproposal",
        ["dedupe_hash"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_idempotency_key",
        "alertseverityproposal",
        ["idempotency_key"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_openai_file_id",
        "alertseverityproposal",
        ["openai_file_id"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_proposed_severity",
        "alertseverityproposal",
        ["proposed_severity"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_provider_id",
        "alertseverityproposal",
        ["provider_id"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_provider_type",
        "alertseverityproposal",
        ["provider_type"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_sync_status",
        "alertseverityproposal",
        ["sync_status"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_tenant_id",
        "alertseverityproposal",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "idx_alertseverityproposal_tenant_status",
        "alertseverityproposal",
        ["tenant_id", "sync_status"],
        unique=False,
    )
    op.create_index(
        "idx_alertseverityproposal_tenant_created_at",
        "alertseverityproposal",
        ["tenant_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "idx_alertseverityproposal_tenant_created_at",
        table_name="alertseverityproposal",
    )
    op.drop_index(
        "idx_alertseverityproposal_tenant_status",
        table_name="alertseverityproposal",
    )
    op.drop_index("ix_alertseverityproposal_tenant_id", table_name="alertseverityproposal")
    op.drop_index("ix_alertseverityproposal_sync_status", table_name="alertseverityproposal")
    op.drop_index("ix_alertseverityproposal_provider_type", table_name="alertseverityproposal")
    op.drop_index("ix_alertseverityproposal_provider_id", table_name="alertseverityproposal")
    op.drop_index(
        "ix_alertseverityproposal_proposed_severity",
        table_name="alertseverityproposal",
    )
    op.drop_index("ix_alertseverityproposal_openai_file_id", table_name="alertseverityproposal")
    op.drop_index("ix_alertseverityproposal_idempotency_key", table_name="alertseverityproposal")
    op.drop_index("ix_alertseverityproposal_dedupe_hash", table_name="alertseverityproposal")
    op.drop_index(
        "ix_alertseverityproposal_current_severity",
        table_name="alertseverityproposal",
    )
    op.drop_index("ix_alertseverityproposal_created_by", table_name="alertseverityproposal")
    op.drop_index(
        "ix_alertseverityproposal_alert_fingerprint",
        table_name="alertseverityproposal",
    )
    op.drop_table("alertseverityproposal")
