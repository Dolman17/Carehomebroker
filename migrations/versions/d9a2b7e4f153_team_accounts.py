"""team accounts and permissions

Revision ID: d9a2b7e4f153
Revises: c8f1a6d3e942
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "d9a2b7e4f153"
down_revision = "c8f1a6d3e942"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "team",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("team_type", sa.String(20), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["created_by_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_team_team_type", "team", ["team_type"])
    op.create_table(
        "team_membership",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("team_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="viewer"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("joined_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["team_id"], ["team.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("team_id", "user_id", name="uq_team_membership_user"),
    )
    for column in ("team_id", "user_id", "role", "status"):
        op.create_index(f"ix_team_membership_{column}", "team_membership", [column])
    op.create_table(
        "team_invitation",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("team_id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("invited_by_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("accepted_at", sa.DateTime()),
        sa.Column("revoked_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["team_id"], ["team.id"]),
        sa.ForeignKeyConstraint(["invited_by_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("team_id", "email", "token_hash", "expires_at"):
        op.create_index(f"ix_team_invitation_{column}", "team_invitation", [column], unique=(column == "token_hash"))
    with op.batch_alter_table("listing") as batch:
        batch.add_column(sa.Column("team_id", sa.Integer()))
        batch.create_foreign_key("fk_listing_team", "team", ["team_id"], ["id"])
        batch.create_index("ix_listing_team_id", ["team_id"])
    with op.batch_alter_table("shortlist_item") as batch:
        batch.drop_constraint("uq_shortlist_item_buyer_listing", type_="unique")
        batch.add_column(sa.Column("team_id", sa.Integer()))
        batch.create_foreign_key("fk_shortlist_item_team", "team", ["team_id"], ["id"])
        batch.create_index("ix_shortlist_item_team_id", ["team_id"])
        batch.create_unique_constraint("uq_shortlist_item_team_listing", ["team_id", "listing_id"])
    with op.batch_alter_table("saved_search") as batch:
        batch.drop_constraint("uq_saved_search_buyer_name", type_="unique")
        batch.add_column(sa.Column("team_id", sa.Integer()))
        batch.create_foreign_key("fk_saved_search_team", "team", ["team_id"], ["id"])
        batch.create_index("ix_saved_search_team_id", ["team_id"])
        batch.create_unique_constraint("uq_saved_search_team_name", ["team_id", "name"])


def downgrade():
    with op.batch_alter_table("saved_search") as batch:
        batch.drop_constraint("uq_saved_search_team_name", type_="unique")
        batch.drop_index("ix_saved_search_team_id")
        batch.drop_constraint("fk_saved_search_team", type_="foreignkey")
        batch.drop_column("team_id")
        batch.create_unique_constraint("uq_saved_search_buyer_name", ["buyer_id", "name"])
    with op.batch_alter_table("shortlist_item") as batch:
        batch.drop_constraint("uq_shortlist_item_team_listing", type_="unique")
        batch.drop_index("ix_shortlist_item_team_id")
        batch.drop_constraint("fk_shortlist_item_team", type_="foreignkey")
        batch.drop_column("team_id")
        batch.create_unique_constraint("uq_shortlist_item_buyer_listing", ["buyer_id", "listing_id"])
    with op.batch_alter_table("listing") as batch:
        batch.drop_index("ix_listing_team_id")
        batch.drop_constraint("fk_listing_team", type_="foreignkey")
        batch.drop_column("team_id")
    op.drop_table("team_invitation")
    op.drop_table("team_membership")
    op.drop_table("team")
