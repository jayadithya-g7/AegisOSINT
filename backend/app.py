"""
AegisOSINT - Central Threat Intelligence Engine & API Gateway
FastAPI Application serving REST endpoints for Multimodal Data Collection,
Evidence Validation, Entity Correlation, Risk Scoring, Reporting, and Interactive UI.
"""

import os
import json
import base64
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .modules.domain_scanner import DomainScanner
from .modules.visual_matcher import VisualMatcher
from .modules.social_detector import SocialMediaDetector
from .modules.communication_nlp import CommunicationNLPAnalyzer
from .modules.entity_graph import EntityCorrelationGraph
from .modules.risk_engine import RiskScoringEngine
from .modules.evidence_locker import EvidenceLocker
from .modules.report_generator import ReportGenerator

# Initialize FastAPI app
app = FastAPI(
    title="AegisOSINT - Automated Brand Impersonation & Fraud Intelligence Platform",
    version="1.0.0",
    description="End-to-end OSINT platform for detecting fake domains, cloned logos, fraudulent communication, and cybercrime networks."
)

# Enable CORS for workbench
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize core intelligence engines
domain_scanner = DomainScanner()
visual_matcher = VisualMatcher()
social_detector = SocialMediaDetector()
nlp_analyzer = CommunicationNLPAnalyzer()
threat_graph = EntityCorrelationGraph()
risk_engine = RiskScoringEngine()
evidence_locker = EvidenceLocker()
report_generator = ReportGenerator()

# Load sample cases into graph on startup
BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
SAMPLE_CASES_PATH = os.path.join(DATA_DIR, "sample_cases.json")


def populate_initial_graph():
    """Seeds graph with sample investigation intelligence."""
    if os.path.exists(SAMPLE_CASES_PATH):
        try:
            with open(SAMPLE_CASES_PATH, "r", encoding="utf-8") as f:
                cases = json.load(f)
                for case in cases:
                    brand = case.get("target_brand", "")
                    primary_dom = case.get("primary_threat_domain", "")
                    infra = case.get("infrastructure", {})
                    social = case.get("social_impersonation", {})
                    wallet = case.get("crypto_wallet")

                    threat_graph.ingest_domain_intelligence(
                        domain=primary_dom,
                        target_brand=brand,
                        ip_addresses=infra.get("ip_addresses", []),
                        registrar=infra.get("registrar"),
                        nameservers=infra.get("nameservers", []),
                        ssl_issuer=infra.get("ssl_issuer"),
                        associated_social=social.get("handle"),
                        crypto_wallet=wallet,
                        asn=infra.get("asn")
                    )

                    # Also ingest associated domains
                    for assoc_dom in case.get("associated_domains", []):
                        if assoc_dom != primary_dom:
                            threat_graph.ingest_domain_intelligence(
                                domain=assoc_dom,
                                target_brand=brand,
                                ip_addresses=infra.get("ip_addresses", []),
                                registrar=infra.get("registrar"),
                                nameservers=infra.get("nameservers", []),
                                ssl_issuer=infra.get("ssl_issuer"),
                                asn=infra.get("asn")
                            )
        except Exception as e:
            print(f"Error seeding graph: {e}")

populate_initial_graph()


# Request / Response Schemas
class DomainScanRequest(BaseModel):
    brand: str
    tld: Optional[str] = "com"
    check_live: Optional[bool] = True

class SingleDomainCheckRequest(BaseModel):
    domain: str
    brand: str

class SocialScanRequest(BaseModel):
    handle: str
    display_name: str
    bio: str
    followers: int = 0
    following: int = 0
    account_age_days: int = 365
    platform: str = "Twitter/X"
    authentic_brand: str = "PayPal"
    authentic_handle: str = "@PayPal"
    is_verified: bool = False

class CommunicationScanRequest(BaseModel):
    text: str
    sender: Optional[str] = None
    claimed_brand: Optional[str] = None

class CompositeRiskRequest(BaseModel):
    domain_score: float = 0.0
    infra_score: float = 0.0
    visual_score: float = 0.0
    content_nlp_score: float = 0.0
    social_score: float = 0.0
    graph_centrality_score: float = 0.0
    context_flags: Optional[List[str]] = None

class IngestEntityRequest(BaseModel):
    domain: str
    target_brand: str
    ip_addresses: List[str]
    registrar: Optional[str] = None
    nameservers: Optional[List[str]] = None
    ssl_issuer: Optional[str] = None
    associated_social: Optional[str] = None
    crypto_wallet: Optional[str] = None
    asn: Optional[str] = None

class RecordEvidenceRequest(BaseModel):
    target_uri: str
    artifact_type: str
    content: str
    metadata: Optional[Dict[str, Any]] = None

class VerifyEvidenceRequest(BaseModel):
    evidence_id: str
    current_content: str

class GenerateReportRequest(BaseModel):
    case_id: str
    brand_name: str
    investigator: str
    target_entity: str
    risk_summary: Dict[str, Any]
    iocs: Dict[str, List[str]]


# REST Endpoints
@app.get("/api/status")
def get_system_status():
    """Returns platform operational telemetry and capabilities."""
    metrics = threat_graph.calculate_graph_metrics()
    return {
        "status": "OPERATIONAL",
        "system": "AegisOSINT Enterprise Threat Intelligence Platform",
        "version": "1.0.0",
        "engines": {
            "domain_scanner": "ACTIVE (Typosquat, Combosquat, Homoglyphs, DNS, SSL, RDAP)",
            "visual_matcher": "ACTIVE (pHash, dHash, aHash, wHash, Color Correlation)",
            "social_detector": "ACTIVE (Cross-Platform Handle Mimicry, Bio NLP, Badging)",
            "communication_nlp": "ACTIVE (Urgency Cues, Credential Harvesting, Sender Spoofing)",
            "entity_graph": "ACTIVE (Heterogeneous Correlation, Centrality, Syndicates)",
            "risk_engine": "ACTIVE (Calibrated Multi-Vector Formula, Synergy Bonus)",
            "evidence_locker": "ACTIVE (SHA-256/SHA-3, Immutable Hash-Chained Ledger)",
            "report_generator": "ACTIVE (Courtroom Dossiers, ICANN Takedowns, STIX 2.1)"
        },
        "telemetry": {
            "graph_nodes": metrics.get("total_nodes", 0),
            "graph_edges": metrics.get("total_edges", 0),
            "active_syndicates_tracked": metrics.get("syndicates_count", 0),
            "evidence_records_sealed": len(evidence_locker.list_evidence())
        }
    }


@app.get("/api/cases")
def list_cases():
    """Lists preloaded and ongoing investigation cases."""
    if os.path.exists(SAMPLE_CASES_PATH):
        with open(SAMPLE_CASES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    """Retrieves specific case dossier."""
    if os.path.exists(SAMPLE_CASES_PATH):
        with open(SAMPLE_CASES_PATH, "r", encoding="utf-8") as f:
            cases = json.load(f)
            for c in cases:
                if c.get("case_id") == case_id:
                    return c
    raise HTTPException(status_code=404, detail="Investigation case not found")


@app.post("/api/scan/domain")
def scan_brand_domains(req: DomainScanRequest):
    """Generates typosquatting, combosquatting, homoglyphs, and evaluates risk."""
    permutations = domain_scanner.generate_permutations(req.brand, req.tld or "com", max_per_type=8)

    # Perform sample resolution & scoring on top generated domains
    scored_results = []
    for perm in permutations[:15]:
        dom = perm["domain"]
        dns_res = domain_scanner.resolve_dns(dom) if req.check_live else {"resolved": False, "ip_addresses": []}
        ssl_res = {"has_ssl": False, "is_free_cert": False}
        risk = domain_scanner.evaluate_domain_risk(dom, req.brand, dns_res, ssl_res)
        scored_results.append({
            **perm,
            "dns": dns_res,
            "ssl": ssl_res,
            "risk": risk
        })

    # Sort highest risk first
    scored_results.sort(key=lambda x: x["risk"]["risk_score"], reverse=True)

    return {
        "brand": req.brand,
        "total_permutations_generated": len(permutations),
        "analyzed_sample": scored_results,
        "all_permutations": permutations
    }


@app.post("/api/scan/domain/single")
def scan_single_domain(req: SingleDomainCheckRequest):
    """Performs deep probe on a specific domain."""
    dns_info = domain_scanner.resolve_dns(req.domain)
    ssl_info = domain_scanner.inspect_ssl(req.domain)
    rdap_info = domain_scanner.inspect_whois_rdap(req.domain)
    risk_info = domain_scanner.evaluate_domain_risk(req.domain, req.brand, dns_info, ssl_info)

    # Automatically preserve evidence
    evidence = evidence_locker.record_evidence(
        target_uri=f"domain://{req.domain}",
        artifact_type="DOMAIN_FORENSIC_SNAPSHOT",
        content={
            "domain": req.domain,
            "brand": req.brand,
            "dns": dns_info,
            "ssl": ssl_info,
            "rdap": rdap_info,
            "risk": risk_info
        }
    )

    return {
        "domain": req.domain,
        "brand": req.brand,
        "dns": dns_info,
        "ssl": ssl_info,
        "rdap": rdap_info,
        "risk": risk_info,
        "evidence_receipt": evidence
    }


@app.post("/api/scan/visual")
async def scan_visual_logo(
    file: Optional[UploadFile] = File(None),
    suspect_base64: Optional[str] = Form(None),
    target_brand: Optional[str] = Form(None)
):
    """Performs visual matching of suspect logo against reference brand assets."""
    image_bytes = None
    if file:
        image_bytes = await file.read()
    elif suspect_base64:
        # Decode base64
        if "," in suspect_base64:
            suspect_base64 = suspect_base64.split(",")[1]
        image_bytes = base64.b64decode(suspect_base64)
    else:
        # If no input provided, use the sample paypal logo as suspect
        ref_path = os.path.join(visual_matcher.reference_dir, f"{target_brand.lower() if target_brand else 'paypal'}.png")
        if os.path.exists(ref_path):
            with open(ref_path, "rb") as f:
                image_bytes = f.read()
        else:
            raise HTTPException(status_code=400, detail="No suspect image uploaded.")

    # Match against reference brand library
    results = visual_matcher.match_against_brand_library(image_bytes)

    # If target_brand requested, provide direct comparison
    brand_comparison = None
    if target_brand:
        ref_file = os.path.join(visual_matcher.reference_dir, f"{target_brand.lower()}.png")
        if os.path.exists(ref_file):
            brand_comparison = visual_matcher.compare_images(image_bytes, ref_file)

    # Record evidence
    evidence = evidence_locker.record_evidence(
        target_uri=f"image://suspect_logo_{target_brand or 'unknown'}",
        artifact_type="VISUAL_LOGO_MATCH",
        content={"match_score": results["top_match"]["composite_visual_score"] if results["top_match"] else 0}
    )

    return {
        "visual_library_matches": results,
        "direct_brand_comparison": brand_comparison,
        "evidence_receipt": evidence
    }


@app.post("/api/scan/social")
def scan_social_profile(req: SocialScanRequest):
    """Evaluates social media profile impersonation."""
    profile_dict = {
        "handle": req.handle,
        "display_name": req.display_name,
        "bio": req.bio,
        "followers": req.followers,
        "following": req.following,
        "account_age_days": req.account_age_days,
        "platform": req.platform,
        "is_verified": req.is_verified
    }
    analysis = social_detector.analyze_profile(profile_dict, req.authentic_brand, req.authentic_handle)
    generated_variants = social_detector.generate_suspect_handles(req.authentic_handle, max_variants=10)

    # Record evidence
    evidence = evidence_locker.record_evidence(
        target_uri=f"social://{req.platform}/{req.handle}",
        artifact_type="SOCIAL_PROFILE_SNAPSHOT",
        content=analysis
    )

    return {
        "profile_analysis": analysis,
        "predictive_squatting_handles": generated_variants,
        "evidence_receipt": evidence
    }


@app.post("/api/scan/communication")
def scan_communication(req: CommunicationScanRequest):
    """Evaluates message/email payload for scam, urgency, and credential theft signals."""
    analysis = nlp_analyzer.analyze_communication(
        text=req.text,
        sender=req.sender,
        claimed_brand=req.claimed_brand
    )

    evidence = evidence_locker.record_evidence(
        target_uri=f"comm://{req.sender or 'anonymous_lure'}",
        artifact_type="COMMUNICATION_NLP_ANALYSIS",
        content=analysis
    )

    return {
        "nlp_analysis": analysis,
        "evidence_receipt": evidence
    }


@app.post("/api/evaluate/composite")
def evaluate_composite_risk(req: CompositeRiskRequest):
    """Calculates weighted composite risk index across multimodal threat vectors."""
    res = risk_engine.compute_composite_risk(
        domain_score=req.domain_score,
        infra_score=req.infra_score,
        visual_score=req.visual_score,
        content_nlp_score=req.content_nlp_score,
        social_score=req.social_score,
        graph_centrality_score=req.graph_centrality_score,
        context_flags=req.context_flags
    )
    return res


@app.get("/api/graph")
def get_threat_graph():
    """Exports entire network graph in Cytoscape.js format along with centrality metrics."""
    cyto = threat_graph.export_to_cytoscape_json()
    metrics = threat_graph.calculate_graph_metrics()
    return {
        "graph": cyto,
        "metrics": metrics
    }


@app.post("/api/graph/correlate")
def correlate_threat_entity(req: IngestEntityRequest):
    """Dynamically ingests and correlates a new entity in the threat network."""
    threat_graph.ingest_domain_intelligence(
        domain=req.domain,
        target_brand=req.target_brand,
        ip_addresses=req.ip_addresses,
        registrar=req.registrar,
        nameservers=req.nameservers,
        ssl_issuer=req.ssl_issuer,
        associated_social=req.associated_social,
        crypto_wallet=req.crypto_wallet,
        asn=req.asn
    )
    return threat_graph.export_to_cytoscape_json()


@app.get("/api/evidence")
def list_evidence_ledger():
    """Returns immutable chain-of-custody ledger records."""
    return evidence_locker.list_evidence(limit=100)


@app.post("/api/evidence/record")
def record_evidence_artifact(req: RecordEvidenceRequest):
    """Cryptographically hashes and seals a new evidence artifact."""
    return evidence_locker.record_evidence(
        target_uri=req.target_uri,
        artifact_type=req.artifact_type,
        content=req.content,
        metadata=req.metadata
    )


@app.post("/api/evidence/verify")
def verify_evidence_integrity(req: VerifyEvidenceRequest):
    """Checks artifact hash against immutable ledger to verify tamper-free status."""
    return evidence_locker.verify_evidence(req.evidence_id, req.current_content)


@app.post("/api/report/generate")
def generate_forensic_report(req: GenerateReportRequest):
    """Assembles comprehensive dossier, takedown letters, and STIX 2.1 intelligence package."""
    # Retrieve recent evidence
    recent_ev = evidence_locker.list_evidence(limit=10)
    graph_metrics = threat_graph.calculate_graph_metrics()

    dossier = report_generator.generate_investigation_dossier(
        case_id=req.case_id,
        brand_name=req.brand_name,
        investigator=req.investigator,
        target_entity=req.target_entity,
        risk_summary=req.risk_summary,
        evidence_records=recent_ev,
        graph_insights=graph_metrics,
        iocs=req.iocs
    )

    stix_bundle = report_generator.export_stix21_bundle(
        case_id=req.case_id,
        brand_name=req.brand_name,
        target_entity=req.target_entity,
        iocs=req.iocs
    )

    return {
        "dossier": dossier,
        "stix21_bundle": stix_bundle
    }


# Static Frontend Mounting
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def serve_frontend():
        index_file = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "AegisOSINT API Operational. Frontend index not found."}
