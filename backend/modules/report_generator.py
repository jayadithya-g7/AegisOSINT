"""
AegisOSINT - Investigation Reporting & Takedown Dossier Generator
Generates comprehensive forensic investigation reports, ICANN-compliant registrar takedown letters,
and STIX 2.1 threat intelligence JSON bundles.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class ReportGenerator:
    """Produces courtroom/takedown-ready forensic dossiers and standardized threat intelligence exports."""

    def generate_investigation_dossier(
        self,
        case_id: str,
        brand_name: str,
        investigator: str,
        target_entity: str,
        risk_summary: Dict[str, Any],
        evidence_records: List[Dict[str, Any]],
        graph_insights: Dict[str, Any],
        iocs: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Assembles a full structured investigation dossier."""
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        dossier = {
            "case_id": case_id,
            "title": f"FORENSIC OSINT INVESTIGATION DOSSIER: Brand Impersonation of '{brand_name}'",
            "generation_timestamp_utc": timestamp_utc,
            "investigator": investigator,
            "target_brand": brand_name,
            "primary_subject": target_entity,
            "executive_summary": (
                f"On {timestamp_utc[:10]}, the AegisOSINT automated cyber threat intelligence system "
                f"identified an active brand impersonation and online fraud campaign targeting '{brand_name}'. "
                f"The subject '{target_entity}' demonstrates a composite risk rating of {risk_summary.get('risk_score')}/100 "
                f"({risk_summary.get('severity')}). Multi-vector analysis confirmed infrastructure deceptive staging, "
                f"visual brand mimicry, and coordinated link correlation."
            ),
            "threat_assessment": risk_summary,
            "indicators_of_compromise": iocs,
            "evidence_chain_of_custody": evidence_records,
            "infrastructure_graph_topology": graph_insights,
            "takedown_notices": {
                "registrar_abuse_letter": self.generate_registrar_takedown(brand_name, target_entity, iocs, evidence_records),
                "hosting_abuse_letter": self.generate_hosting_takedown(brand_name, target_entity, iocs)
            }
        }
        return dossier

    def generate_registrar_takedown(
        self,
        brand_name: str,
        domain: str,
        iocs: Dict[str, List[str]],
        evidence_records: List[Dict[str, Any]]
    ) -> str:
        """Generates formal, legally-grounded Registrar Abuse Report notice."""
        ips = ", ".join(iocs.get("ip_addresses", ["Unknown IP"]))
        evidence_hashes = "\n".join([
            f"- Evidence ID: {e.get('evidence_id')}\n  Artifact: {e.get('artifact_type')}\n  SHA-256: {e.get('sha256_hash')}\n  Timestamp: {e.get('timestamp_utc')}"
            for e in evidence_records[:3]
        ]) or "- Evidence captured and hashed according to NIST SP 800-86 forensic standards."

        return f"""SUBJECT: URGENT: Brand Impersonation & Malicious Phishing Takedown Request - Domain: {domain}

Dear Abuse and Legal Team,

This is a formal notification and urgent takedown request regarding the unauthorized brand impersonation, deceptive typosquatting, and fraudulent activity hosted via domain:

DOMAIN IN VIOLATION: {domain}
TARGETED TRADEMARK: {brand_name}
RESOLVED IP ADDRESS(ES): {ips}
DATE/TIME OF DETECTION (UTC): {datetime.now(timezone.utc).isoformat()}

1. NATURE OF INFRINGEMENT & ABUSE:
The subject domain is actively impersonating the legitimate trademark and digital presence of '{brand_name}'.
Our automated OSINT and forensic verification suite has identified that this domain is configured to deceive end users, harvest unauthorized user credentials/payments, and inflict irreparable reputational and financial harm.

2. FORENSIC EVIDENCE & CRYPTOGRAPHIC CHAIN OF CUSTODY:
Forensic snapshots of the domain have been preserved with immutable cryptographic hashes:
{evidence_hashes}

3. REQUESTED ACTION:
Pursuant to ICANN Registrar Accreditation Agreement (RAA) Section 3.18, and your Acceptable Use Policy regarding deceptive and abusive registrations:
- Immediate suspension / cancellation / delegation hold (clientHold / serverHold) of the domain '{domain}'.
- Disablement of active DNS resolution to protect internet users from ongoing fraud.

Please confirm receipt and acknowledge remediation within 24 hours.

Sincerely,
AegisOSINT Brand Protection & Incident Response Unit
Email: abuse-response@aegis-osint.org
"""

    def generate_hosting_takedown(
        self,
        brand_name: str,
        target_entity: str,
        iocs: Dict[str, List[str]]
    ) -> str:
        """Generates hosting provider cease-and-desist abuse notification."""
        ips = ", ".join(iocs.get("ip_addresses", ["Unknown IP"]))
        return f"""SUBJECT: URGENT: Cease & Desist / Phishing Infrastructure Hosting Abuse - Server: {ips}

Dear Abuse Department,

We have detected that infrastructure operated within your Autonomous System (ASN) is actively hosting fraudulent content and impersonation kits targeting {brand_name}.

INFRASTRUCTURE DETAILS:
- Domain: {target_entity}
- Host IP(s): {ips}
- Incident Type: Fraudulent Brand Impersonation & Credential Harvesting

In accordance with your terms of service regarding fraud and malicious hosting, we formally demand the immediate termination or null-routing of the hosting services supporting this malicious resource.

Full forensic evidence packages have been sealed and are available upon request.

Respectfully,
AegisOSINT Digital Risk Protection Team
"""

    def export_stix21_bundle(
        self,
        case_id: str,
        brand_name: str,
        target_entity: str,
        iocs: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Generates an OASIS STIX 2.1 standard JSON threat intelligence bundle."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        bundle_id = f"bundle--{uuid.uuid4()}"

        # 1. Identity (Victim Brand)
        brand_identity_id = f"identity--{uuid.uuid4()}"
        brand_identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": brand_identity_id,
            "created": now,
            "modified": now,
            "name": brand_name,
            "identity_class": "organization",
            "sectors": ["financial-services", "technology"]
        }

        # 2. Threat Actor / Campaign
        campaign_id = f"campaign--{uuid.uuid4()}"
        campaign = {
            "type": "campaign",
            "spec_version": "2.1",
            "id": campaign_id,
            "created": now,
            "modified": now,
            "name": f"Brand Impersonation Syndicate against {brand_name}",
            "description": f"Targeted online brand impersonation and typosquatting campaign involving {target_entity}",
            "objective": "Credential harvesting and financial theft"
        }

        # 3. Indicators
        indicators = []
        relationships = []

        # Domain Indicator
        domain_ind_id = f"indicator--{uuid.uuid4()}"
        domain_ind = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": domain_ind_id,
            "created": now,
            "modified": now,
            "name": f"Malicious Domain: {target_entity}",
            "pattern": f"[domain-name:value = '{target_entity}']",
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity", "brand-impersonation"]
        }
        indicators.append(domain_ind)

        # Relate domain indicator to campaign
        relationships.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": domain_ind_id,
            "target_ref": campaign_id
        })

        # IP Indicators
        for ip in iocs.get("ip_addresses", []):
            ip_ind_id = f"indicator--{uuid.uuid4()}"
            ip_ind = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ip_ind_id,
                "created": now,
                "modified": now,
                "name": f"Phishing Host IP: {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": now,
                "indicator_types": ["malicious-activity"]
            }
            indicators.append(ip_ind)
            relationships.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": ip_ind_id,
                "target_ref": campaign_id
            })

        # Relate campaign targets brand
        relationships.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": "targets",
            "source_ref": campaign_id,
            "target_ref": brand_identity_id
        })

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": [brand_identity, campaign] + indicators + relationships
        }
        return bundle
