"""
AegisOSINT API Integration Tests
Tests all REST endpoints served by FastAPI gateway.
"""

import pytest
from starlette.testclient import TestClient
from backend.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_api_status(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OPERATIONAL"
    assert "domain_scanner" in data["engines"]


def test_api_cases(client):
    res = client.get("/api/cases")
    assert res.status_code == 200
    cases = res.json()
    assert len(cases) >= 4
    assert any(c["target_brand"] == "PayPal" for c in cases)


def test_api_scan_domain(client):
    payload = {"brand": "PayPal", "tld": "com", "check_live": False}
    res = client.post("/api/scan/domain", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["total_permutations_generated"] > 0
    assert len(data["analyzed_sample"]) > 0


def test_api_scan_communication(client):
    payload = {
        "text": "URGENT: Your account has been suspended! Click https://paypal-fake.top/auth within 24 hours.",
        "sender": "alert@scam.org",
        "claimed_brand": "PayPal"
    }
    res = client.post("/api/scan/communication", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["nlp_analysis"]["fraud_score"] >= 70


def test_api_graph_export(client):
    res = client.get("/api/graph")
    assert res.status_code == 200
    data = res.json()
    assert "elements" in data["graph"]
    assert len(data["graph"]["elements"]["nodes"]) > 0


def test_api_evidence_ledger(client):
    res = client.get("/api/evidence")
    assert res.status_code == 200
    records = res.json()
    assert len(records) > 0
    assert "sha256_hash" in records[0]


def test_api_report_generation(client):
    payload = {
        "case_id": "TEST-INT-001",
        "brand_name": "PayPal",
        "investigator": "Automated Tester",
        "target_entity": "paypal-spoof.top",
        "risk_summary": {"risk_score": 92.0, "severity": "CRITICAL"},
        "iocs": {
            "domains": ["paypal-spoof.top"],
            "ip_addresses": ["185.220.101.5"]
        }
    }
    res = client.post("/api/report/generate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "dossier" in data
    assert "stix21_bundle" in data
    assert data["stix21_bundle"]["type"] == "bundle"


def test_api_live_deep_scan(client):
    payload = {
        "target": "github.com",
        "brand": "GitHub"
    }
    res = client.post("/api/scan/live-deep", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_real_live_scan"] is True
    assert "dns" in data
    assert "rdap" in data
    assert "ssl" in data
    assert "http" in data
    assert "evidence_receipt" in data
