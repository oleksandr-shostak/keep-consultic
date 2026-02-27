"""Add incident severity proposal knowledge base table

Revision ID: f2d4b8c1a901
Revises: 9b73d1e5afc4
Create Date: 2026-02-27 13:20:00.000000

"""

import sqlalchemy as sa
import sqlmodel
from alembic import op
from sqlalchemy_utils import UUIDType

# revision identifiers, used by Alembic.
revision = "f2d4b8c1a901"
down_revision = "9b73d1e5afc4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incidentseverityproposal",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("tenant_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("incident_id", UUIDType(binary=False), nullable=False),
        sa.Column(
            "current_severity", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column(
            "proposed_severity", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("reason", sa.TEXT(), nullable=False),
        sa.Column("incident_name", sa.TEXT(), nullable=False),
        sa.Column("incident_status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("incident_snapshot", sa.JSON(), nullable=False),
        sa.Column("alerts_count", sa.Integer(), nullable=False),
        sa.Column("alerts_snapshot", sa.JSON(), nullable=False),
        sa.Column("created_by", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("idempotency_key", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("dedupe_hash", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("sync_status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("sync_status_reason", sa.TEXT(), nullable=True),
        sa.Column("sync_attempts", sa.Integer(), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(), nullable=True),
        sa.Column("updated_by", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column(
            "is_deleted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("deleted_by", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.Column("openai_file_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column(
            "openai_vector_file_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True
        ),
        sa.Column("vector_store_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "dedupe_hash",
            name="uq_incidentseverityproposal_tenant_dedupe_hash",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_incidentseverityproposal_tenant_idempotency_key",
        ),
    )
    op.create_index(
        "ix_incidentseverityproposal_tenant_id",
        "incidentseverityproposal",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_current_severity",
        "incidentseverityproposal",
        ["current_severity"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_proposed_severity",
        "incidentseverityproposal",
        ["proposed_severity"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_incident_status",
        "incidentseverityproposal",
        ["incident_status"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_created_by",
        "incidentseverityproposal",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_idempotency_key",
        "incidentseverityproposal",
        ["idempotency_key"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_dedupe_hash",
        "incidentseverityproposal",
        ["dedupe_hash"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_sync_status",
        "incidentseverityproposal",
        ["sync_status"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_updated_by",
        "incidentseverityproposal",
        ["updated_by"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_is_deleted",
        "incidentseverityproposal",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_deleted_by",
        "incidentseverityproposal",
        ["deleted_by"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_openai_file_id",
        "incidentseverityproposal",
        ["openai_file_id"],
        unique=False,
    )
    op.create_index(
        "ix_incidentseverityproposal_openai_vector_file_id",
        "incidentseverityproposal",
        ["openai_vector_file_id"],
        unique=False,
    )
    op.create_index(
        "idx_incidentseverityproposal_tenant_status",
        "incidentseverityproposal",
        ["tenant_id", "sync_status"],
        unique=False,
    )
    op.create_index(
        "idx_incidentseverityproposal_tenant_created_at",
        "incidentseverityproposal",
        ["tenant_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "idx_incidentseverityproposal_tenant_incident_deleted",
        "incidentseverityproposal",
        ["tenant_id", "incident_id", "is_deleted"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "idx_incidentseverityproposal_tenant_incident_deleted",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "idx_incidentseverityproposal_tenant_created_at",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "idx_incidentseverityproposal_tenant_status",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_openai_vector_file_id",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_openai_file_id",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_deleted_by",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_is_deleted",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_updated_by",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_sync_status",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_dedupe_hash",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_idempotency_key",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_created_by",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_incident_status",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_proposed_severity",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_current_severity",
        table_name="incidentseverityproposal",
    )
    op.drop_index(
        "ix_incidentseverityproposal_tenant_id",
        table_name="incidentseverityproposal",
    )
    op.drop_table("incidentseverityproposal")
