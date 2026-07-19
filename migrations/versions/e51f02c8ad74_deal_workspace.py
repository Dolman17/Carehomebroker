"""deal workspace

Revision ID: e51f02c8ad74
Revises: d7b391e4a620
Create Date: 2026-07-19
"""

from alembic import op
import sqlalchemy as sa


revision = "e51f02c8ad74"
down_revision = "d7b391e4a620"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "workspace_message",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("introduction_id", sa.Integer(), nullable=False),
        sa.Column("author_id", sa.Integer(), nullable=False),
        sa.Column("message_type", sa.String(length=20), nullable=False, server_default="message"),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["author_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["introduction_id"], ["introductions.id"]),
        sa.ForeignKeyConstraint(["resolved_by_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("introduction_id", "message_type", "created_at"):
        op.create_index(op.f(f"ix_workspace_message_{column}"), "workspace_message", [column], unique=False)

    op.create_table(
        "workspace_task",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("introduction_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="todo"),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["created_by_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["introduction_id"], ["introductions.id"]),
        sa.ForeignKeyConstraint(["owner_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("introduction_id", "owner_id", "status", "due_date"):
        op.create_index(op.f(f"ix_workspace_task_{column}"), "workspace_task", [column], unique=False)

    op.create_table(
        "workspace_milestone",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("introduction_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="planned"),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["created_by_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["introduction_id"], ["introductions.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("introduction_id", "status"):
        op.create_index(op.f(f"ix_workspace_milestone_{column}"), "workspace_milestone", [column], unique=False)


def downgrade():
    for column in ("status", "introduction_id"):
        op.drop_index(op.f(f"ix_workspace_milestone_{column}"), table_name="workspace_milestone")
    op.drop_table("workspace_milestone")
    for column in ("due_date", "status", "owner_id", "introduction_id"):
        op.drop_index(op.f(f"ix_workspace_task_{column}"), table_name="workspace_task")
    op.drop_table("workspace_task")
    for column in ("created_at", "message_type", "introduction_id"):
        op.drop_index(op.f(f"ix_workspace_message_{column}"), table_name="workspace_message")
    op.drop_table("workspace_message")
