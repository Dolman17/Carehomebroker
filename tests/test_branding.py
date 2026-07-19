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


def test_landing_page_has_conversion_paths_and_confidentiality_copy(client):
    response = client.get("/")
    page = response.get_data(as_text=True)

    assert "Sell your business" in page
    assert "Explore opportunities" in page
    assert "For business owners" in page
    assert "For buyers & investors" in page
    assert "Confidentiality is part of the process" in page
    assert 'href="/pricing?role=seller"' in page
    assert 'href="/pricing?role=buyer"' in page


def test_landing_page_explains_the_full_marketplace(client):
    page = client.get("/").get_data(as_text=True)

    assert "One marketplace, multiple sectors" in page
    assert "The tools to move from interest to introduction" in page
    assert "A structured journey after the match" in page
    assert "Bring in specialist support when the deal needs it" in page
    assert "What to expect from Ownerlane" in page
    assert "Will my business name be shown publicly?" in page
    assert "How are buyers matched to opportunities?" in page
    assert 'href="/register/valuer"' in page


def test_landing_page_respects_listing_access(client):
    anonymous_page = client.get("/").get_data(as_text=True)
    assert "SECRET BUSINESS NAME" not in anonymous_page
    assert "£4,000,000" not in anonymous_page
    assert "Premium access" in anonymous_page

    client.post(
        "/login",
        data={"email": "buyer@example.test", "password": "Testing123!"},
    )
    premium_page = client.get("/").get_data(as_text=True)
    assert "SECRET BUSINESS NAME" in premium_page
    assert "£4,000,000" in premium_page


def test_public_marketplace_pages_use_ownerlane(client):
    for path in ("/listings", "/pricing", "/login"):
        response = client.get(path)
        assert response.status_code == 200
        page = response.get_data(as_text=True)
        assert "Ownerlane" in page
        assert "Kaijo" not in page
        assert "Care Home Broker" not in page


def test_legal_footer_links_to_complete_notice_set(client):
    page = client.get("/").get_data(as_text=True)

    expected_links = (
        "/privacy",
        "/cookies",
        "/terms",
        "/marketplace-terms",
        "/acceptable-use",
        "/legal-notice",
        "/accessibility",
        "/complaints",
    )
    for path in expected_links:
        assert f'href="{path}"' in page


def test_legal_pages_are_public_and_cross_linked(client):
    expected_pages = {
        "/privacy": "Personal data we collect",
        "/cookies": "Cookies Ownerlane currently uses",
        "/terms": "Information, not professional advice",
        "/marketplace-terms": "Ownerlane’s role",
        "/acceptable-use": "You must not",
        "/legal-notice": "Website operator",
        "/accessibility": "Conformance status",
        "/complaints": "How to complain",
    }

    for path, copy in expected_pages.items():
        response = client.get(path)
        assert response.status_code == 200
        page = response.get_data(as_text=True)
        assert copy in page
        assert "Privacy notice" in page
        assert "Cookie notice" in page
        assert "Marketplace terms" in page


def test_live_brand_sources_do_not_reference_legacy_names():
    sources = [ROOT / "app.py", ROOT / "readme.md"]
    sources.extend((ROOT / "templates").rglob("*.html"))

    for source in sources:
        content = source.read_text(encoding="utf-8").lower()
        assert "kaijo" not in content, source
        assert "care home broker" not in content, source


def test_rebrand_preserves_route_contract():
    rules = {rule.rule for rule in app.url_map.iter_rules()}

    assert len(rules) == 111
    assert "/" in rules
    assert "/listings" in rules
    assert "/pricing" in rules
    assert "/seller/dashboard" in rules
    assert "/buyer/dashboard" in rules
    assert "/privacy" in rules
    assert "/cookies" in rules
    assert "/terms" in rules
    assert "/marketplace-terms" in rules
    assert "/acceptable-use" in rules
    assert "/legal-notice" in rules
    assert "/accessibility" in rules
    assert "/complaints" in rules
    assert "/forgot-password" in rules
    assert "/verify-email/<token>" in rules
    assert "/notifications" in rules
