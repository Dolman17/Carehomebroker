"""integrations foundation

Revision ID: e0b3c8f5a264
Revises: d9a2b7e4f153
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "e0b3c8f5a264"
down_revision = "d9a2b7e4f153"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "integration_api_token",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("team_id", sa.Integer(), sa.ForeignKey("team.id")),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("token_prefix", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("scopes", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime()),
        sa.Column("expires_at", sa.DateTime()),
        sa.Column("revoked_at", sa.DateTime()),
    )
    for column in ("user_id", "team_id", "token_prefix", "expires_at"):
        op.create_index(f"ix_integration_api_token_{column}", "integration_api_token", [column])
    op.create_index("ix_integration_api_token_token_hash", "integration_api_token", ["token_hash"], unique=True)
    op.create_table(
        "webhook_endpoint",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("team_id", sa.Integer(), sa.ForeignKey("team.id")),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("url", sa.String(1000), nullable=False),
        sa.Column("signing_salt", sa.String(64), nullable=False),
        sa.Column("event_types", sa.String(500), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("disabled_at", sa.DateTime()),
    )
    for column in ("user_id", "team_id", "is_active"):
        op.create_index(f"ix_webhook_endpoint_{column}", "webhook_endpoint", [column])
    op.create_index("ix_webhook_endpoint_signing_salt", "webhook_endpoint", ["signing_salt"], unique=True)
    op.create_table(
        "webhook_delivery",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("webhook_endpoint.id"), nullable=False),
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_attempt_at", sa.DateTime()),
        sa.Column("delivered_at", sa.DateTime()),
        sa.Column("response_status", sa.Integer()),
        sa.Column("response_excerpt", sa.String(500)),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    for column in ("endpoint_id", "event_type", "status", "next_attempt_at"):
        op.create_index(f"ix_webhook_delivery_{column}", "webhook_delivery", [column])
    op.create_index("ix_webhook_delivery_event_id", "webhook_delivery", ["event_id"], unique=True)


def downgrade():
    op.drop_table("webhook_delivery")
    op.drop_table("webhook_endpoint")
    op.drop_table("integration_api_token")
