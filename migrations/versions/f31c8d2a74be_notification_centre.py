"""notification centre

Revision ID: f31c8d2a74be
Revises: e72a6b4c91df
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa


revision = "f31c8d2a74be"
down_revision = "e72a6b4c91df"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "notification_preference",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column(
            "email_mode",
            sa.String(length=20),
            nullable=False,
            server_default="weekly",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
    )

    op.create_table(
        "notification",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("target_url", sa.String(length=500), nullable=True),
        sa.Column("dedupe_key", sa.String(length=255), nullable=False),
        sa.Column(
            "email_eligible", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column("read_at", sa.DateTime(), nullable=True),
        sa.Column("email_sent_at", sa.DateTime(), nullable=True),
        sa.Column("digest_sent_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id", "dedupe_key", name="uq_notification_user_dedupe"
        ),
    )
    op.create_index(
        op.f("ix_notification_event_type"),
        "notification",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_user_id"),
        "notification",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_notification_user_unread",
        "notification",
        ["user_id", "read_at"],
        unique=False,
    )


def downgrade():
    op.drop_index("ix_notification_user_unread", table_name="notification")
    op.drop_index(op.f("ix_notification_user_id"), table_name="notification")
    op.drop_index(op.f("ix_notification_event_type"), table_name="notification")
    op.drop_table("notification")
    op.drop_table("notification_preference")
