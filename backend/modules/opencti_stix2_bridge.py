"""
AegisOSINT - OpenCTI STIX 2.1 & MISP Threat Intelligence Interchange Bridge
Synthesized from OpenCTI-Platform/opencti and MISP/MISP.

Key Capabilities:
- Full OASIS STIX 2.1 Bundle serialization (identity, threat-actor, attack-pattern, indicator, infrastructure, relationship).
- MISP 2.4 Event JSON export with categorized IoC attributes and Galaxy tagging.
- One-click copy & paste interchange with enterprise SOC/CTI platforms.
- Cryptographic deterministic UUID generation (UUIDv5) for persistent graph node tracking.
"""

import uuid
import datetime
from typing import List, Dict, Any, Optional

STIX_NAMESPACE = uuid.UUID("f98e2942-d611-47ea-a417-641579d47226")


def generate_stix_id(type_name: str, seed_value: str) -> str:
    """Generates deterministic STIX 2.1 UUIDv5 identifier."""
    val_uuid = uuid.uuid5(STIX_NAMESPACE, f"{type_name}:{seed_value}")
    return f"{type_name}--{val_uuid}"


class OpenCTISTIX2Bridge:
    """
    Translates AegisOSINT brand impersonation investigation records into
    interoperable OpenCTI STIX 2.1 bundles and MISP Event JSON.
    """

    def export_stix21_bundle(self, case_id: str, brand_name: str, target_domain: str,
                             resolved_ips: List[str] = None, threat_score: int = 85,
                             threat_actor_type: str = "Organized BEC Phishing Syndicate") -> Dict[str, Any]:
        """
        Builds a complete, valid OASIS STIX 2.1 bundle ready for direct ingestion
        into OpenCTI.
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects = []

        # 1. Identity: Target Victim Brand
        identity_id = generate_stix_id("identity", brand_name.lower())
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": brand_name,
            "identity_class": "organization",
            "description": f"Target organization and brand identity under impersonation attack: {brand_name}"
        }
        objects.append(identity_obj)

        # 2. Threat Actor
        threat_actor_id = generate_stix_id("threat-actor", f"{case_id}-{target_domain}")
        threat_actor_obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": threat_actor_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Adversary Cluster ({target_domain})",
            "threat_actor_types": ["crime-syndicate", "impersonator"],
            "description": f"{threat_actor_type} staging brand impersonation infrastructure targeting {brand_name}.",
            "sophistication": "intermediate" if threat_score >= 70 else "minimal",
            "resource_level": "individual" if threat_score < 60 else "organization",
            "primary_motivation": "financial-gain"
        }
        objects.append(threat_actor_obj)

        # 3. Infrastructure: Malicious Domain
        infra_id = generate_stix_id("infrastructure", target_domain)
        infra_obj = {
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": infra_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Impersonation Domain ({target_domain})",
            "infrastructure_types": ["phishing", "command-and-control"],
            "description": f"Unauthenticated lookalike infrastructure masquerading as official {brand_name} web portals."
        }
        objects.append(infra_obj)

        # 4. Indicator: Domain Name Pattern
        indicator_id = generate_stix_id("indicator", f"domain:{target_domain}")
        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Malicious Domain Indicator: {target_domain}",
            "pattern": f"[domain-name:value = '{target_domain}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "confidence": min(100, max(20, threat_score)),
            "indicator_types": ["malicious-activity", "phishing"]
        }
        objects.append(indicator_obj)

        # 5. Attack Patterns (MITRE ATT&CK)
        mitre_t1566 = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": generate_stix_id("attack-pattern", "T1566.002"),
            "created": now_iso,
            "modified": now_iso,
            "name": "Spearphishing Link",
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": "T1566.002",
                "url": "https://attack.mitre.org/techniques/T1566/002/"
            }]
        }
        objects.append(mitre_t1566)

        # 6. Relationships (STIX 2.1 Graph Edges)
        # Relationship: Threat Actor uses Infrastructure
        rel_uses = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": "uses",
            "source_ref": threat_actor_id,
            "target_ref": infra_id
        }
        objects.append(rel_uses)

        # Relationship: Threat Actor targets Identity
        rel_targets = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": "targets",
            "source_ref": threat_actor_id,
            "target_ref": identity_id
        }
        objects.append(rel_targets)

        # Relationship: Indicator indicates Infrastructure
        rel_indicates = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": infra_id
        }
        objects.append(rel_indicates)

        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects,
            "metadata": {
                "generated_by": "AegisOSINT OpenCTI STIX2 Engine",
                "case_id": case_id,
                "objects_count": len(objects)
            }
        }

    def export_misp_event(self, case_id: str, brand_name: str, target_domain: str,
                          resolved_ips: List[str] = None, threat_score: int = 85) -> Dict[str, Any]:
        """
        Builds a valid MISP 2.4 Event JSON structure ready for import into MISP instances.
        """
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        attributes = [
            {
                "type": "domain",
                "category": "Network activity",
                "to_ids": True,
                "value": target_domain,
                "comment": f"Suspect brand impersonation domain targeting {brand_name}"
            },
            {
                "type": "url",
                "category": "Network activity",
                "to_ids": True,
                "value": f"https://{target_domain}/",
                "comment": "Suspect landing page URL"
            }
        ]

        for ip in (resolved_ips or []):
            attributes.append({
                "type": "ip-dst",
                "category": "Network activity",
                "to_ids": True,
                "value": ip,
                "comment": f"Host IP resolution for impersonation domain {target_domain}"
            })

        return {
            "Event": {
                "info": f"Brand Impersonation & Phishing Campaign: {brand_name} ({target_domain})",
                "date": date_str,
                "threat_level_id": "1" if threat_score >= 80 else ("2" if threat_score >= 60 else "3"),
                "analysis": "2",
                "distribution": "1",
                "published": False,
                "Attribute": attributes,
                "Tag": [
                    {"name": "tlp:amber", "colour": "#ffc000"},
                    {"name": "misp-galaxy:threat-actor=\"Phishing Syndicate\"", "colour": "#d9534f"},
                    {"name": "brand-abuse", "colour": "#5bc0de"},
                    {"name": f"target:{brand_name.lower()}", "colour": "#0275d8"}
                ]
            }
        }
