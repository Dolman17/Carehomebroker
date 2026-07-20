import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def test_initial_migration_builds_a_fresh_database(tmp_path):
    repository = Path(__file__).resolve().parents[1]
    database = tmp_path / "fresh.db"
    env = os.environ.copy()
    env.update(
        DATABASE_URL=f"sqlite:///{database}",
        SECRET_KEY="migration-test-secret",
        RUN_MIGRATIONS_ON_START="0",
    )

    result = subprocess.run(
        [sys.executable, "-m", "flask", "--app", "app.py", "db", "upgrade"],
        cwd=repository,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr

    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()

    assert revision is not None
    assert {
        "user",
        "listing",
        "buyer_profile",
        "seller_profiles",
        "valuer_profiles",
        "introductions",
        "deals",
        "subscriptions",
        "listing_analytics_event",
        "adviser_category",
        "adviser_service",
        "adviser_request",
        "adviser_quote",
        "adviser_review",
        "benchmark_consent",
        "benchmark_record",
        "benchmark_report",
        "team",
        "team_membership",
        "team_invitation",
        "integration_api_token",
        "webhook_endpoint",
        "webhook_delivery",
    } <= tables
    assert revision[0] == "e0b3c8f5a264"
