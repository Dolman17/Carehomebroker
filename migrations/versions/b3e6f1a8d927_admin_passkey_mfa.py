"""administrator passkey MFA

Revision ID: b3e6f1a8d927
Revises: a2d5e0b7c486
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "b3e6f1a8d927"
down_revision = "a2d5e0b7c486"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user") as batch:
        batch.add_column(sa.Column("webauthn_user_handle", sa.String(64)))
        batch.create_unique_constraint(
            "uq_user_webauthn_user_handle", ["webauthn_user_handle"]
        )

    op.create_table(
        "admin_passkey",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("name", sa.String(80), nullable=False, server_default="Passkey"),
        sa.Column("credential_id", sa.String(1024), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("transports", sa.String(255)),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime()),
    )
    op.create_index("ix_admin_passkey_user_id", "admin_passkey", ["user_id"])
    op.create_index("ix_admin_passkey_credential_id", "admin_passkey", ["credential_id"], unique=True)

    op.create_table(
        "webauthn_challenge",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("purpose", sa.String(24), nullable=False),
        sa.Column("challenge", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime()),
    )
    op.create_index("ix_webauthn_challenge_user_id", "webauthn_challenge", ["user_id"])
    op.create_index("ix_webauthn_challenge_purpose", "webauthn_challenge", ["purpose"])
    op.create_index("ix_webauthn_challenge_expires_at", "webauthn_challenge", ["expires_at"])


def downgrade():
    op.drop_table("webauthn_challenge")
    op.drop_table("admin_passkey")
    with op.batch_alter_table("user") as batch:
        batch.drop_constraint("uq_user_webauthn_user_handle", type_="unique")
        batch.drop_column("webauthn_user_handle")
