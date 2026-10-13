"""
AegisOSINT - Open-Source Online Threat Feeds & Reconnaissance Tests
Validates OpenPhish/Phishunt threat feeds, PhoneInfoga phone OSINT,
Reverse Image Search dispatchers (TinEye/Yandex), Dark Web Brand Intelligence
(OnionSearch/Ahmia.fi), and WebTech stack fingerprinter.
"""

import pytest
from starlette.testclient import TestClient
from backend.app import app
from backend.modules.open_threat_feeds import OpenThreatFeeds


@pytest.fixture
def client():
    return TestClient(app)


def test_open_threat_feeds_unit_phishing():
    feeds = OpenThreatFeeds()
    res = feeds.check_live_phishing_feeds(target="paypal-security-login.top", brand="PayPal")

    assert "target" in res
    assert "openphish" in res
    assert "phishunt" in res
    assert "overall_verdict" in res
    assert res["openphish"]["status"] in ["FEED_PARSED_SUCCESS", "FALLBACK_HEURISTIC_APPLIED"]
    assert isinstance(res["overall_verdict"]["is_confirmed_phishing"], bool)
    assert res["overall_verdict"]["threat_severity"] in ["CRITICAL", "HIGH", "CLEAN"]


def test_open_threat_feeds_unit_phone_infoga():
    feeds = OpenThreatFeeds()

    # Toll-Free fraud helpline test
    res = feeds.analyze_fraud_phone_number("+1-800-442-1234")
    assert res["e164"] == "+18004421234"
    assert res["line_type"] == "TOLL_FREE"
    assert res["fraud_risk_score"] >= 70
    assert res["severity"] == "CRITICAL"
    assert any("toll-free" in ind.lower() for ind in res["fraud_indicators"])
    assert "reputation_searches" in res
    assert "whocalledme" in res["reputation_searches"]
    assert "800notes" in res["reputation_searches"]
    assert "scampulse" in res["reputation_searches"]

    # UK standard number test
    uk_res = feeds.analyze_fraud_phone_number("+44 20 7946 0958")
    assert uk_res["country_code"] == "+44"
    assert uk_res["probable_country"] == "UK"
    assert uk_res["line_type"] in ["LANDLINE", "MOBILE"]


def test_open_threat_feeds_unit_reverse_image_search():
    feeds = OpenThreatFeeds()
    res = feeds.generate_reverse_image_search_links("https://example.com/assets/brand-logo.png")

    assert res["image_url"] == "https://example.com/assets/brand-logo.png"
    assert "search_engines" in res
    engines = res["search_engines"]
    assert "tineye" in engines
    assert "yandex" in engines
    assert "lens" in engines
    assert "bing" in engines

    assert "tineye.com/search?url=" in engines["tineye"]["url"]
    assert "yandex.com/images/search?rpt=imageview&url=" in engines["yandex"]["url"]
    assert "lens.google.com/uploadbyurl?url=" in engines["lens"]["url"]
    assert "bing.com/images/search" in engines["bing"]["url"]


def test_open_threat_feeds_unit_darkweb_search():
    feeds = OpenThreatFeeds()
    res = feeds.generate_darkweb_brand_searches(brand="PayPal", domain="paypal.com")

    assert res["brand"] == "PayPal"
    assert "darkweb_gateways" in res
    gateways = res["darkweb_gateways"]
    assert "ahmia_fi" in gateways
    assert "onionland" in gateways
    assert "torlink" in gateways
    assert "ahmia.fi/search/?q=" in gateways["ahmia_fi"]["url"]
    assert "onionsearch" in res["onionsearch_cli_command"]


def test_open_threat_feeds_unit_web_technology():
    feeds = OpenThreatFeeds()
    # Fingerprint a known domain (or fallback heuristic if offline)
    res = feeds.fingerprint_web_technology("https://example.com")

    assert "url" in res
    assert "server" in res
    assert "technologies_detected" in res
    assert "security_headers" in res
    assert "tactical_assessment" in res
    assert isinstance(res["security_headers"], dict)


def test_api_recon_live_phishing_feeds(client):
    resp = client.post("/api/recon/live-phishing-feeds", json={
        "target": "login-chase-update.top",
        "brand": "Chase"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "overall_verdict" in data
    assert "openphish" in data
    assert "phishunt" in data


def test_api_recon_fraud_phone(client):
    resp = client.post("/api/recon/fraud-phone", json={
        "phone_number": "+1-888-555-0199"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["e164"] == "+18885550199"
    assert data["line_type"] == "TOLL_FREE"
    assert data["fraud_risk_score"] >= 65


def test_api_recon_reverse_image_search(client):
    resp = client.post("/api/recon/reverse-image-search", json={
        "image_url": "https://paypal-security-login.top/logo.png"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "search_engines" in data
    assert "tineye" in data["search_engines"]
    assert "yandex" in data["search_engines"]


def test_api_recon_darkweb_search(client):
    resp = client.post("/api/recon/darkweb-search", json={
        "brand": "Netflix",
        "domain": "netflix.com"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["brand"] == "Netflix"
    assert "darkweb_gateways" in data
    assert "ahmia_fi" in data["darkweb_gateways"]


def test_api_recon_web_technology(client):
    resp = client.post("/api/recon/web-technology", json={
        "url": "https://cloudflare.com"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "server" in data
    assert "technologies_detected" in data
    assert "security_headers" in data
