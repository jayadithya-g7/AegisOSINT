"""
AegisOSINT - Multi-Factor Calibrated Risk Scoring Engine
Implements mathematically grounded risk aggregation across domain, infrastructure,
visual mimicry, communication NLP, social impersonation, and graph topology.
"""

from typing import Dict, Any, List, Optional


class RiskScoringEngine:
    """Aggregates multimodal threat telemetry into a calibrated 0-100 Risk Index."""

    # Dimension weights summing to 1.0
    WEIGHTS = {
        "domain": 0.25,
        "infrastructure": 0.20,
        "visual": 0.20,
        "content_nlp": 0.15,
        "social": 0.10,
        "graph_centrality": 0.10
    }

    def compute_composite_risk(
        self,
        domain_score: float = 0.0,
        infra_score: float = 0.0,
        visual_score: float = 0.0,
        content_nlp_score: float = 0.0,
        social_score: float = 0.0,
        graph_centrality_score: float = 0.0,
        context_flags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Computes composite risk score:
        R = sum(w_i * S_i) + SynergyBonus
        """
        w = self.WEIGHTS
        base_score = (
            w["domain"] * domain_score +
            w["infrastructure"] * infra_score +
            w["visual"] * visual_score +
            w["content_nlp"] * content_nlp_score +
            w["social"] * social_score +
            w["graph_centrality"] * graph_centrality_score
        )

        # Count active threat vectors (scores >= 50)
        active_vectors = 0
        if domain_score >= 50: active_vectors += 1
        if infra_score >= 50: active_vectors += 1
        if visual_score >= 50: active_vectors += 1
        if content_nlp_score >= 50: active_vectors += 1
        if social_score >= 50: active_vectors += 1
        if graph_centrality_score >= 50: active_vectors += 1

        # Multi-vector synergy penalty: coordinated campaigns across domains, visuals, and messaging
        synergy_penalty = 0.0
        if active_vectors >= 4:
            synergy_penalty = 20.0
        elif active_vectors >= 3:
            synergy_penalty = 12.0
        elif active_vectors >= 2:
            synergy_penalty = 6.0

        total_score = min(100.0, round(base_score + synergy_penalty, 2))

        # Severity classification
        if total_score >= 80.0:
            severity = "CRITICAL"
            action_priority = "P1 - Immediate Emergency Intervention"
            recommendations = [
                "Issue expedited Domain Registrar Abuse Notice for domain suspension under ICANN UDRP / Emergency Takedown.",
                "Submit Hosting Provider Cease-and-Desist to server ASN abuse contact.",
                "Deploy Google Safe Browsing and Microsoft SmartScreen malicious URL reports.",
                "Trigger social media account impersonation takedown via platform partner API.",
                "Push IOCs (Domain, IP, Cert hash) to enterprise SIEM/EDR blocklists and DNS RPZ firewalls."
            ]
        elif total_score >= 60.0:
            severity = "HIGH"
            action_priority = "P2 - Priority Takedown & Blocking"
            recommendations = [
                "File formal Brand Abuse Ticket with Registrar and CDN provider.",
                "Monitor for active phishing kit staging and email exchange activation.",
                "Add destination domain and associated IPs to security watchlist."
            ]
        elif total_score >= 40.0:
            severity = "MEDIUM"
            action_priority = "P3 - Active Intelligence Monitoring"
            recommendations = [
                "Schedule automated daily re-scans for DNS change or weaponization.",
                "Correlate infrastructure with existing known fraud syndicates."
            ]
        elif total_score >= 20.0:
            severity = "LOW"
            action_priority = "P4 - Routine Surveillance"
            recommendations = [
                "Retain record in OSINT repository for longitudinal tracking."
            ]
        else:
            severity = "BENIGN"
            action_priority = "P5 - No Immediate Action Required"
            recommendations = [
                "Entity displays no malicious indicators. Whitelisted or benign."
            ]

        return {
            "risk_score": total_score,
            "severity": severity,
            "action_priority": action_priority,
            "active_threat_vectors_count": active_vectors,
            "synergy_penalty_applied": synergy_penalty,
            "dimension_breakdown": {
                "domain_lexical": {"score": domain_score, "weighted": round(w["domain"] * domain_score, 2)},
                "infrastructure": {"score": infra_score, "weighted": round(w["infrastructure"] * infra_score, 2)},
                "visual_mimicry": {"score": visual_score, "weighted": round(w["visual"] * visual_score, 2)},
                "content_nlp": {"score": content_nlp_score, "weighted": round(w["content_nlp"] * content_nlp_score, 2)},
                "social_impersonation": {"score": social_score, "weighted": round(w["social"] * social_score, 2)},
                "graph_syndicate": {"score": graph_centrality_score, "weighted": round(w["graph_centrality"] * graph_centrality_score, 2)}
            },
            "recommendations": recommendations,
            "context_flags": context_flags or []
        }
