import pytest
from starlette.testclient import TestClient

from backend.app import app
from backend.modules.email_security_dmarc import EmailSecurityDmarcAnalyzer


@pytest.fixture
def analyzer():
    return EmailSecurityDmarcAnalyzer()


@pytest.fixture
def client():
    return TestClient(app)


def test_dmarc_analyzer_live_audit(analyzer):
    # Test authentic brand domain with strict DMARC enforcement (e.g. google.com or paypal.com)
    res = analyzer.audit_domain_email_security("google.com", "Google")
    assert res["domain"] == "google.com"
    assert "spf_audit" in res
    assert "dmarc_audit" in res
    assert "bimi_audit" in res
    assert isinstance(res["spf_audit"]["has_spf"], bool)
    assert isinstance(res["dmarc_audit"]["has_dmarc"], bool)
    assert res["spoofing_vulnerability_score"] >= 0.0


def test_dmarc_analyzer_unregistered_or_vulnerable_domain(analyzer):
    # Test domain with missing DMARC/SPF
    res = analyzer.audit_domain_email_security("fake-unregistered-test-portal-1234.top", "Brand")
    assert res["spf_audit"]["is_spoofable"] is True
    assert res["dmarc_audit"]["is_enforced"] is False
    assert res["spoofing_vulnerability_score"] >= 70.0
    assert len(res["remediation_actions"]) >= 1


def test_api_dmarc_endpoint(client):
    res = client.post("/api/scan/dmarc-spf", json={"domain": "paypal.com", "brand": "PayPal"})
    assert res.status_code == 200
    data = res.json()
    assert data["domain"] == "paypal.com"
    assert "dmarc_audit" in data
    assert "spf_audit" in data


def test_api_sigma_yara_endpoint(client):
    payload = {
        "domain": "phish-paypal-update.top",
        "brand": "PayPal",
        "ip_addresses": ["192.0.2.1"]
    }
    res = client.post("/api/recon/sigma-yara", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "sigma_rule_yaml" in data
    assert "yara_rule" in data
    assert "phish-paypal-update.top" in data["sigma_rule_yaml"]
    assert "Phishing_Kit_" in data["yara_rule"]
