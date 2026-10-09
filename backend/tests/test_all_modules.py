"""
AegisOSINT Comprehensive Test Suite
Validates all intelligence engines: domain scanner, visual matcher, social detector,
communication NLP, entity graph, risk engine, and evidence locker.
"""

import os
import pytest
from backend.modules.domain_scanner import DomainScanner, calculate_levenshtein, calculate_similarity_ratio
from backend.modules.visual_matcher import VisualMatcher
from backend.modules.social_detector import SocialMediaDetector
from backend.modules.communication_nlp import CommunicationNLPAnalyzer
from backend.modules.entity_graph import EntityCorrelationGraph
from backend.modules.risk_engine import RiskScoringEngine
from backend.modules.evidence_locker import EvidenceLocker
from backend.modules.report_generator import ReportGenerator


def test_domain_scanner_permutations():
    scanner = DomainScanner()
    perms = scanner.generate_permutations("paypal", "com", max_per_type=5)
    assert len(perms) > 10
    domains = [p["domain"] for p in perms]
    # Check that combosquatting or typosquatting domains are present
    assert any("login" in d or "secure" in d for d in domains)
    assert calculate_levenshtein("paypal", "paypa1") == 1
    assert calculate_similarity_ratio("paypal", "paypal") == 1.0


def test_domain_risk_evaluation():
    scanner = DomainScanner()
    dns_res = {"resolved": True, "ip_addresses": ["185.220.101.5"], "mail_servers": ["mx.evil.top"]}
    ssl_res = {"has_ssl": True, "is_free_cert": True, "issuer": "Let's Encrypt"}
    risk = scanner.evaluate_domain_risk("paypal-security-login.top", "paypal", dns_res, ssl_res)
    assert risk["risk_score"] >= 70
    assert risk["severity"] in ["HIGH", "CRITICAL"]
    assert len(risk["risk_factors"]) >= 3


def test_visual_matcher_hashes():
    matcher = VisualMatcher()
    results = matcher.match_against_brand_library(
        os.path.join(matcher.reference_dir, "paypal.png")
    )
    assert results["top_match"] is not None
    assert results["top_match"]["brand"] == "Paypal"
    assert results["top_match"]["composite_visual_score"] >= 95.0
    assert results["top_match"]["verdict"] == "CONFIRMED_CLONED_LOGO"


def test_social_detector():
    detector = SocialMediaDetector()
    variants = detector.generate_suspect_handles("@PayPal", max_variants=10)
    assert len(variants) > 0
    assert any("support" in v["handle"] for v in variants)

    suspect_profile = {
        "handle": "@PayPaI_SupportOfficial",
        "display_name": "PayPal Support Official ✔️",
        "bio": "DM us to verify wallet and claim refund wa.me/18005550199",
        "followers": 15,
        "following": 900,
        "account_age_days": 10,
        "platform": "Twitter/X",
        "is_verified": False
    }
    analysis = detector.analyze_profile(suspect_profile, "PayPal", "@PayPal")
    assert analysis["impersonation_score"] >= 75
    assert analysis["severity"] in ["HIGH", "CRITICAL"]
    assert len(analysis["indicators"]) >= 3


def test_communication_nlp():
    analyzer = CommunicationNLPAnalyzer()
    text = (
        "URGENT: Unauthorized transaction detected! Your PayPal account will be "
        "permanently suspended within 24 hours. Enter your password and verify identity immediately: "
        "https://paypal-security-login.top/auth"
    )
    result = analyzer.analyze_communication(
        text=text,
        sender="security@fraudulent-mail.com",
        claimed_brand="PayPal"
    )
    assert result["fraud_score"] >= 80
    assert result["severity"] == "CRITICAL"
    assert len(result["extracted_urls"]) == 1
    assert "https://paypal-security-login.top/auth" in result["extracted_urls"]
    assert result["subscores"]["urgency_coercion"] > 0


def test_entity_graph_and_centrality():
    graph = EntityCorrelationGraph()
    graph.ingest_domain_intelligence(
        domain="paypal-security-login.top",
        target_brand="PayPal",
        ip_addresses=["185.220.101.5"],
        registrar="NameCheap, Inc.",
        nameservers=["ns1.evil.top", "ns2.evil.top"],
        ssl_issuer="Let's Encrypt",
        associated_social="@PayPaI_Support",
        asn="AS49870"
    )
    # Add a second co-hosted domain on the same IP
    graph.ingest_domain_intelligence(
        domain="paypa1-support.xyz",
        target_brand="PayPal",
        ip_addresses=["185.220.101.5"],
        registrar="NameCheap, Inc."
    )

    metrics = graph.calculate_graph_metrics()
    assert metrics["total_nodes"] >= 6
    assert metrics["total_edges"] >= 6
    assert metrics["syndicates_count"] >= 1
    # Check that IP address is a high-degree hub
    pivots = metrics["top_infrastructure_pivots"]
    assert any(p["node_id"] == "ip:185.220.101.5" for p in pivots)


def test_risk_scoring_engine():
    engine = RiskScoringEngine()
    result = engine.compute_composite_risk(
        domain_score=90.0,
        infra_score=85.0,
        visual_score=95.0,
        content_nlp_score=90.0,
        social_score=85.0,
        graph_centrality_score=80.0
    )
    assert result["risk_score"] >= 85.0
    assert result["severity"] == "CRITICAL"
    assert result["synergy_penalty_applied"] > 0
    assert len(result["recommendations"]) >= 3


def test_evidence_locker_and_verification():
    locker = EvidenceLocker()
    sample_content = {"domain": "paypal-fake.top", "ip": "1.2.3.4"}
    rec = locker.record_evidence(
        target_uri="domain://paypal-fake.top",
        artifact_type="DOMAIN_SNAPSHOT",
        content=sample_content
    )
    assert rec["evidence_id"] is not None
    assert len(rec["sha256_hash"]) == 64
    assert rec["hmac_seal"] is not None

    # Verify matching content passes
    verification = locker.verify_evidence(rec["evidence_id"], sample_content)
    assert verification["verified"] is True
    assert verification["status"] == "VALID_TAMPER_FREE"

    # Verify altered content fails
    tampered_verification = locker.verify_evidence(rec["evidence_id"], {"domain": "altered.top"})
    assert tampered_verification["verified"] is False
    assert tampered_verification["status"] == "TAMPER_DETECTED"


def test_report_and_stix_generator():
    gen = ReportGenerator()
    iocs = {"domains": ["phish.top"], "ip_addresses": ["1.2.3.4"]}
    risk = {"risk_score": 90, "severity": "CRITICAL"}
    dossier = gen.generate_investigation_dossier(
        case_id="TEST-001",
        brand_name="PayPal",
        investigator="Analyst",
        target_entity="phish.top",
        risk_summary=risk,
        evidence_records=[],
        graph_insights={},
        iocs=iocs
    )
    assert dossier["case_id"] == "TEST-001"
    assert "ICANN" in dossier["takedown_notices"]["registrar_abuse_letter"]

    stix = gen.export_stix21_bundle(
        case_id="TEST-001",
        brand_name="PayPal",
        target_entity="phish.top",
        iocs=iocs
    )
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) >= 4
