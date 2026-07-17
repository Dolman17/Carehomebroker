from pathlib import Path

from app import app


ROOT = Path(__file__).resolve().parents[1]


def test_ownerlane_homepage_brand(client):
    response = client.get("/")

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Ownerlane" in page
    assert "Where businesses find their next owner" in page
    assert "ownerlane-logo.svg" in page
    assert "Kaijo" not in page
    assert "Care Home Broker" not in page


def test_public_marketplace_pages_use_ownerlane(client):
    for path in ("/listings", "/pricing", "/login"):
        response = client.get(path)
        assert response.status_code == 200
        page = response.get_data(as_text=True)
        assert "Ownerlane" in page
        assert "Kaijo" not in page
        assert "Care Home Broker" not in page


def test_live_brand_sources_do_not_reference_legacy_names():
    sources = [ROOT / "app.py", ROOT / "readme.md"]
    sources.extend((ROOT / "templates").rglob("*.html"))

    for source in sources:
        content = source.read_text(encoding="utf-8").lower()
        assert "kaijo" not in content, source
        assert "care home broker" not in content, source


def test_rebrand_preserves_route_contract():
    rules = {rule.rule for rule in app.url_map.iter_rules()}

    assert len(rules) == 72
    assert "/" in rules
    assert "/listings" in rules
    assert "/pricing" in rules
    assert "/seller/dashboard" in rules
    assert "/buyer/dashboard" in rules
