"""
AegisOSINT - Advanced GitHub Repositories Integration Tests
Validates openSquat (atenreiro/opensquat), Holehe (megadose/holehe),
Pagodo (opsdisk/pagodo), Robofinder (Spix0r/robofinder), and OpenCTI/MISP bridges.
"""

import pytest
from starlette.testclient import TestClient
from backend.app import app
from backend.modules.opensquat_engine import OpenSquatEngine, calculate_levenshtein, calculate_similarity_score
from backend.modules.holehe_email_scanner import HoleheEmailScanner
from backend.modules.opencti_stix2_bridge import OpenCTISTIX2Bridge
from backend.modules.pagodo_dork_engine import PagodoDorkEngine
from backend.modules.robofinder_forensics import RobofinderForensics


@pytest.fixture
def client():
    return TestClient(app)


def test_opensquat_engine_generation_and_audit():
    engine = OpenSquatEngine()

    # Levenshtein distance
    assert calculate_levenshtein("paypal", "paypal") == 0
    assert calculate_levenshtein("paypal", "paypa1") == 1
    assert calculate_similarity_score("paypal", "paypa1.com") >= 0.8

    # Candidate generation
    candidates = engine.generate_squat_candidates("apple", "com", max_candidates=15)
    assert len(candidates) >= 10
    types = [c["permutation_type"] for c in candidates]
    assert any("Homoglyph" in t or "Combosquat" in t or "Bitsquatting" in t for t in types)

    # Full audit
    audit = engine.audit_brand("paypal", "com", check_live_dns=False, limit=10)
    assert audit["target_brand"] == "paypal"
    assert len(audit["candidates"]) == 10
    assert "recommendation" in audit


def test_holehe_email_scanner():
    scanner = HoleheEmailScanner()

    # Gravatar hash
    grav = scanner.check_gravatar("test@example.com")
    assert grav["platform"] == "Gravatar / Automattic"
    assert len(grav["hash_md5"]) == 32

    # Disposable email scan
    res = scanner.scan_email_identity("phisher@guerrillamail.com")
    assert res["is_disposable_burner"] is True
    assert res["risk_score"] >= 70
    assert res["severity"] == "CRITICAL"

    # Free webmail with deceptive prefix
    res2 = scanner.scan_email_identity("security-billing-support991@gmail.com")
    assert res2["is_free_webmail"] is True
    assert res2["risk_score"] >= 50
    assert len(res2["additional_lookup_targets"]) >= 4


def test_opencti_stix2_and_misp_export():
    bridge = OpenCTISTIX2Bridge()

    # STIX 2.1 Bundle
    bundle = bridge.export_stix21_bundle(
        case_id="CASE-2026-001",
        brand_name="PayPal",
        target_domain="secure-paypal-login.top",
        resolved_ips=["192.0.2.1"],
        threat_score=92
    )
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    types = [o["type"] for o in bundle["objects"]]
    assert "identity" in types
    assert "threat-actor" in types
    assert "infrastructure" in types
    assert "indicator" in types
    assert "relationship" in types

    # MISP Event JSON
    misp = bridge.export_misp_event(
        case_id="CASE-2026-001",
        brand_name="PayPal",
        target_domain="secure-paypal-login.top",
        resolved_ips=["192.0.2.1"],
        threat_score=92
    )
    assert "Event" in misp
    assert len(misp["Event"]["Attribute"]) >= 2
    assert any(a["type"] == "domain" for a in misp["Event"]["Attribute"])


def test_pagodo_dork_engine():
    engine = PagodoDorkEngine()
    res = engine.generate_dorks("Microsoft", "microsoft.com")
    assert res["total_dorks"] == 12
    for d in res["dorks"]:
        assert "google" in d["search_engines"]
        assert "duckduckgo" in d["search_engines"]
        assert "bing" in d["search_engines"]
        assert "yandex" in d["search_engines"]
        assert "dork_syntax" in d


def test_robofinder_forensics():
    finder = RobofinderForensics()
    res = finder.analyze_domain_robots("example.com")
    assert "domain" in res
    assert "robots_txt_found" in res
    assert "tactical_assessment" in res


def test_api_endpoints_advanced_integrations(client):
    # 1. openSquat endpoint
    r_os = client.post("/api/recon/opensquat", json={"brand": "chase", "tld": "com", "check_live": False, "limit": 10})
    assert r_os.status_code == 200
    assert r_os.json()["target_brand"] == "chase"

    # 2. Holehe endpoint
    r_ho = client.post("/api/recon/holehe-email", json={"email": "alert@mailinator.com"})
    assert r_ho.status_code == 200
    assert r_ho.json()["is_disposable_burner"] is True

    # 3. Pagodo dorks endpoint
    r_pg = client.post("/api/recon/pagodo-dorks", json={"brand": "Netflix", "legitimate_domain": "netflix.com"})
    assert r_pg.status_code == 200
    assert r_pg.json()["total_dorks"] == 12

    # 4. Robofinder endpoint
    r_rb = client.post("/api/recon/robofinder", json={"domain": "github.com"})
    assert r_rb.status_code == 200
    assert "domain" in r_rb.json()

    # 5. OpenCTI STIX 2.1 endpoint
    r_stix = client.post("/api/export/opencti-stix2", json={
        "case_id": "CASE-TEST",
        "brand_name": "Google",
        "target_domain": "google-security-verify.top"
    })
    assert r_stix.status_code == 200
    assert r_stix.json()["type"] == "bundle"

    # 6. MISP Event endpoint
    r_misp = client.post("/api/export/misp-event", json={
        "case_id": "CASE-TEST",
        "brand_name": "Google",
        "target_domain": "google-security-verify.top"
    })
    assert r_misp.status_code == 200
    assert "Event" in r_misp.json()


def test_favicon_murmur3_hash_calculation():
    from backend.modules.visual_matcher import VisualMatcher
    matcher = VisualMatcher()

    fav = matcher.compute_favicon_murmur3(b"test-favicon-bytes-for-shodan-hash")
    assert fav["shodan_hash"] != 0
    assert len(fav["md5"]) == 32
    assert "http.favicon.hash" in fav["dork"]
    assert "https://www.shodan.io/search" in fav["shodan_search_url"]
    assert "https://search.censys.io/search" in fav["censys_search_url"]

