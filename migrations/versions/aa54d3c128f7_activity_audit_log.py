"""activity audit log

Revision ID: aa54d3c128f7
Revises: f31c8d2a74be
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa


revision = "aa54d3c128f7"
down_revision = "f31c8d2a74be"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_event",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("subject_user_id", sa.Integer(), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("resource_type", sa.String(length=50), nullable=True),
        sa.Column("resource_id", sa.String(length=100), nullable=True),
        sa.Column("summary", sa.String(length=255), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("ip_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["actor_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["subject_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("actor_id", "subject_user_id", "event_type", "resource_type", "created_at"):
        op.create_index(op.f(f"ix_audit_event_{column}"), "audit_event", [column], unique=False)


def downgrade():
    for column in ("created_at", "resource_type", "event_type", "subject_user_id", "actor_id"):
        op.drop_index(op.f(f"ix_audit_event_{column}"), table_name="audit_event")
    op.drop_table("audit_event")
