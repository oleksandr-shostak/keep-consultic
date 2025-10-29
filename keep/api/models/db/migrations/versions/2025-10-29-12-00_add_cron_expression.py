"""Add cron_expression to workflow table

Revision ID: add_cron_expression
Revises: 9dd1be4539e0
Create Date: 2025-10-29 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "add_cron_expression"
down_revision = "9dd1be4539e0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add cron_expression column to workflow table
    with op.batch_alter_table("workflow", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("cron_expression", sa.String(), nullable=True)
        )


def downgrade() -> None:
    # Remove cron_expression column from workflow table
    with op.batch_alter_table("workflow", schema=None) as batch_op:
        batch_op.drop_column("cron_expression")

