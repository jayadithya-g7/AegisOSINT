import pytest
from starlette.testclient import TestClient

from backend.app import app
from backend.modules.cyber_llm_advisor import CyberLLMAdvisor


@pytest.fixture
def advisor():
    return CyberLLMAdvisor()


@pytest.fixture
def client():
    return TestClient(app)


def test_cyber_llm_supported_models(advisor):
    res = advisor.get_supported_models()
    assert res["zero_local_download"] is True
    assert "GLM-5.3-Cyber" in res["models"]
    assert "DeepSeek-R1" in res["models"]
    assert "Qwen2.5-Coder-32B" in res["models"]
    assert any("CyberSecEval" in b for b in res["benchmarks_supported"])


def test_cyber_llm_defense_signatures(advisor):
    sigs = advisor.generate_defense_signatures(
        domain="paypal-verify-account.top",
        brand="PayPal",
        ip_addresses=["198.51.100.42"]
    )
    assert "dns_rpz_zone" in sigs
    assert "suricata_ids_rule" in sigs
    assert "waf_filter_expression" in sigs
    assert "paypal-verify-account.top CNAME ." in sigs["dns_rpz_zone"]
    assert "AEGIS-CTI" in sigs["suricata_ids_rule"]
    assert "paypal" in sigs["waf_filter_expression"]


def test_cyber_llm_threat_analysis(advisor):
    telemetry = {
        "dns": {"ip_addresses": ["185.220.101.5"]},
        "ssl": {"is_free_cert": True, "issuer": "Let's Encrypt"},
        "rdap": {"domain_age_days": 2},
        "http": {"has_login_form": True},
        "risk": {"risk_score": 92.0}
    }
    analysis = advisor.analyze_threat(
        domain="login-chase-update.top",
        brand="Chase",
        telemetry=telemetry,
        model_preference="GLM-5.3-Cyber"
    )

    assert analysis["target_domain"] == "login-chase-update.top"
    assert analysis["target_brand"] == "Chase"
    assert analysis["zero_local_download"] is True
    assert "CyberSecEval" in analysis["benchmark_framework"]
    assert len(analysis["mitre_attack_mappings"]) >= 3
    assert any(m["technique_id"] == "T1566.002" for m in analysis["mitre_attack_mappings"])
    assert any(m["technique_id"] == "T1056.003" for m in analysis["mitre_attack_mappings"])
    assert "TIER_3" in analysis["threat_actor_profiling"]["sophistication_tier"]
    assert len(analysis["recommended_triage_actions"]) >= 3


def test_cyber_llm_api_endpoints(client):
    # GET /api/cyber-llm/models
    res_models = client.get("/api/cyber-llm/models")
    assert res_models.status_code == 200
    data_models = res_models.json()
    assert data_models["zero_local_download"] is True
    assert "GLM-5.3-Cyber" in data_models["models"]

    # POST /api/cyber-llm/analyze
    payload = {
        "domain": "security-appleid-lock.xyz",
        "brand": "Apple",
        "model_preference": "GLM-5.3-Cyber",
        "telemetry": {
            "dns": {"ip_addresses": ["91.108.4.1"]},
            "ssl": {"is_free_cert": True},
            "risk": {"risk_score": 88.0}
        }
    }
    res_analyze = client.post("/api/cyber-llm/analyze", json=payload)
    assert res_analyze.status_code == 200
    data_analyze = res_analyze.json()
    assert data_analyze["target_domain"] == "security-appleid-lock.xyz"
    assert "evidence_receipt" in data_analyze
    assert "sha256_hash" in data_analyze["evidence_receipt"]
