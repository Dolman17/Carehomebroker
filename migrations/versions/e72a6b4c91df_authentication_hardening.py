"""authentication hardening

Revision ID: e72a6b4c91df
Revises: b4d29f6a13c0
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa


revision = "e72a6b4c91df"
down_revision = "b4d29f6a13c0"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user") as batch_op:
        batch_op.add_column(sa.Column("email_verified_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("password_changed_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("last_login_at", sa.DateTime(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "security_stamp",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )

    # Existing users retain access. New registrations are explicitly unverified.
    op.execute(
        sa.text(
            "UPDATE user SET email_verified_at = CURRENT_TIMESTAMP, "
            "password_changed_at = CURRENT_TIMESTAMP"
        )
    )

    op.create_table(
        "login_attempt",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("first_failed_at", sa.DateTime(), nullable=False),
        sa.Column("blocked_until", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash"),
    )
    op.create_index(
        op.f("ix_login_attempt_key_hash"),
        "login_attempt",
        ["key_hash"],
        unique=True,
    )


def downgrade():
    op.drop_index(op.f("ix_login_attempt_key_hash"), table_name="login_attempt")
    op.drop_table("login_attempt")
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("security_stamp")
        batch_op.drop_column("last_login_at")
        batch_op.drop_column("password_changed_at")
        batch_op.drop_column("email_verified_at")
