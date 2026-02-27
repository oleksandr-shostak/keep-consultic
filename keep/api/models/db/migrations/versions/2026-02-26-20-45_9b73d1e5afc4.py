"""Extend alert severity proposals with lifecycle fields

Revision ID: 9b73d1e5afc4
Revises: 4c9e1f3ab2d7
Create Date: 2026-02-26 20:45:00.000000

"""

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision = "9b73d1e5afc4"
down_revision = "4c9e1f3ab2d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("alertseverityproposal") as batch_op:
        batch_op.add_column(
            sa.Column("updated_by", sqlmodel.sql.sqltypes.AutoString(), nullable=True)
        )
        batch_op.add_column(sa.Column("updated_at", sa.DateTime(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "is_deleted",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.add_column(
            sa.Column("deleted_by", sqlmodel.sql.sqltypes.AutoString(), nullable=True)
        )
        batch_op.add_column(sa.Column("deleted_at", sa.DateTime(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "openai_vector_file_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True
            )
        )

    op.create_index(
        "ix_alertseverityproposal_updated_by",
        "alertseverityproposal",
        ["updated_by"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_is_deleted",
        "alertseverityproposal",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_deleted_by",
        "alertseverityproposal",
        ["deleted_by"],
        unique=False,
    )
    op.create_index(
        "ix_alertseverityproposal_openai_vector_file_id",
        "alertseverityproposal",
        ["openai_vector_file_id"],
        unique=False,
    )
    op.create_index(
        "idx_alertseverityproposal_tenant_alert_deleted",
        "alertseverityproposal",
        ["tenant_id", "alert_id", "is_deleted"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "idx_alertseverityproposal_tenant_alert_deleted",
        table_name="alertseverityproposal",
    )
    op.drop_index(
        "ix_alertseverityproposal_openai_vector_file_id",
        table_name="alertseverityproposal",
    )
    op.drop_index(
        "ix_alertseverityproposal_deleted_by",
        table_name="alertseverityproposal",
    )
    op.drop_index(
        "ix_alertseverityproposal_is_deleted",
        table_name="alertseverityproposal",
    )
    op.drop_index(
        "ix_alertseverityproposal_updated_by",
        table_name="alertseverityproposal",
    )

    with op.batch_alter_table("alertseverityproposal") as batch_op:
        batch_op.drop_column("openai_vector_file_id")
        batch_op.drop_column("deleted_at")
        batch_op.drop_column("deleted_by")
        batch_op.drop_column("is_deleted")
        batch_op.drop_column("updated_at")
        batch_op.drop_column("updated_by")
