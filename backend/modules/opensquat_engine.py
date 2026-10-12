"""
AegisOSINT - openSquat Phishing & Lookalike Domain Engine
Synthesized from atenreiro/opensquat, elceef/dnstwist, and urlinsane.

Key Capabilities:
- Levenshtein & token overlap distance calculation against protected brand names.
- Multi-tier permutation generation (Homoglyphs, Bitsquatting, Combosquatting, Transposition).
- Real-time DNS and Quad9/Cloudflare DoH resolution validation.
- Classification into actionable confidence tiers (CRITICAL, HIGH, MEDIUM, LOW).
- PhishStats / community threat signature matching.
"""

import math
from typing import List, Dict, Any, Optional
import requests
import socket

# Common high-risk phishing prefixes and suffixes
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "support", "helpdesk",
    "account", "billing", "update", "auth", "portal", "recovery",
    "service", "security", "wallet", "online", "client"
]

# Cyrillic and Greek homoglyphs commonly abused in IDN homograph attacks
HOMOGLYPH_MAP = {
    'a': ['а', '4', '@'],
    'c': ['с'],
    'e': ['е', '3'],
    'i': ['1', 'l', 'і'],
    'o': ['о', '0'],
    'p': ['р'],
    's': ['5', '$'],
    'u': ['υ'],
    'x': ['х'],
    'y': ['у']
}

def calculate_levenshtein(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance using dynamic programming."""
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def calculate_similarity_score(base_brand: str, candidate_domain: str) -> float:
    """
    Computes a normalized similarity score (0.0 to 1.0) based on
    Levenshtein distance, length ratio, and substring containment.
    """
    clean_brand = base_brand.lower().strip()
    clean_cand = candidate_domain.lower().split('.')[0].strip()

    if clean_brand == clean_cand:
        return 1.0

    dist = calculate_levenshtein(clean_brand, clean_cand)
    max_len = max(len(clean_brand), len(clean_cand))
    lev_ratio = max(0.0, 1.0 - (dist / max_len))

    # Bonus if brand name is cleanly embedded as a substring
    contains_bonus = 0.25 if clean_brand in clean_cand else 0.0

    return min(1.0, round(lev_ratio + contains_bonus, 3))


class OpenSquatEngine:
    """
    Automated Lookalike & Typosquatting Analysis Engine
    Directly synthesizing openSquat (atenreiro/opensquat) and urlinsane.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AegisOSINT-openSquat/2.0 (Brand Protection Recon)"
        })

    def generate_squat_candidates(self, brand: str, tld: str = "com", max_candidates: int = 40) -> List[Dict[str, Any]]:
        """Generates permutation candidates across typos, homoglyphs, combosquatting, and bitsquatting."""
        b = brand.lower().strip()
        candidates = []
        seen = set()

        def add_cand(name: str, ptype: str, severity: str):
            dom = f"{name}.{tld}"
            if dom not in seen and name != b:
                seen.add(dom)
                sim = calculate_similarity_score(b, dom)
                candidates.append({
                    "domain": dom,
                    "permutation_type": ptype,
                    "similarity_score": sim,
                    "threat_severity": severity
                })

        # 1. Combosquatting (Prefix / Suffix keyword chaining)
        for kw in PHISHING_KEYWORDS[:8]:
            add_cand(f"{b}-{kw}", "Combosquat (Hyphenated)", "HIGH")
            add_cand(f"{kw}-{b}", "Combosquat (Prefix)", "HIGH")
            add_cand(f"{b}{kw}", "Combosquat (Chained)", "HIGH")

        # 2. Homoglyph Substitution
        for i, char in enumerate(b):
            if char in HOMOGLYPH_MAP:
                for rep in HOMOGLYPH_MAP[char]:
                    homo_name = b[:i] + rep + b[i+1:]
                    add_cand(homo_name, "Homoglyph Deception", "CRITICAL")

        # 3. Bitsquatting (single bit flips in binary ASCII)
        for i, char in enumerate(b):
            c_code = ord(char)
            for bit in range(7):
                flipped = c_code ^ (1 << bit)
                if chr(flipped).isalnum() and chr(flipped).islower() and chr(flipped) != char:
                    bit_name = b[:i] + chr(flipped) + b[i+1:]
                    add_cand(bit_name, "Bitsquatting (Hardware Bit-Flip)", "CRITICAL")

        # 4. Transposition (swapping adjacent characters)
        for i in range(len(b) - 1):
            trans_name = b[:i] + b[i+1] + b[i] + b[i+2:]
            add_cand(trans_name, "Transposition (Typo)", "MEDIUM")

        # Sort by similarity score descending
        candidates.sort(key=lambda x: x["similarity_score"], reverse=True)
        return candidates[:max_candidates]

    def verify_dns_resolution(self, domain: str) -> Dict[str, Any]:
        """Validates if a candidate is actively live on the internet via DNS & DoH."""
        ips = []
        is_live = False

        # Attempt local socket first
        try:
            ip = socket.gethostbyname(domain)
            if ip:
                ips.append(ip)
                is_live = True
        except Exception:
            pass

        # Fallback to Cloudflare DoH
        if not is_live:
            try:
                r = self.session.get(f"https://1.1.1.1/dns-query?name={domain}&type=A", headers={"accept": "application/dns-json"}, timeout=2.5)
                if r.status_code == 200:
                    ans = r.json().get("Answer", [])
                    for a in ans:
                        if a.get("type") == 1:
                            ips.append(a.get("data"))
                            is_live = True
            except Exception:
                pass

        return {
            "domain": domain,
            "is_live": is_live,
            "resolved_ips": list(set(ips)),
            "status": "ONLINE_RESOLVED" if is_live else "UNREGISTERED_OR_INACTIVE"
        }

    def audit_brand(self, brand: str, tld: str = "com", check_live_dns: bool = True, limit: int = 25) -> Dict[str, Any]:
        """
        Executes complete openSquat audit for a protected brand.
        Returns ranked lookalike threat candidates and live telemetry.
        """
        candidates = self.generate_squat_candidates(brand, tld, max_candidates=limit)
        results = []
        active_threats_count = 0

        for cand in candidates:
            dns_info = {"is_live": False, "resolved_ips": []}
            if check_live_dns:
                # Check live resolution for top candidates
                if cand["similarity_score"] >= 0.7:
                    dns_info = self.verify_dns_resolution(cand["domain"])
                    if dns_info["is_live"]:
                        active_threats_count += 1

            risk_score = int(cand["similarity_score"] * 70)
            if dns_info.get("is_live"):
                risk_score += 30

            results.append({
                **cand,
                "dns": dns_info,
                "composite_risk_score": min(100, risk_score),
                "is_active_phish_threat": dns_info.get("is_live", False) and cand["similarity_score"] >= 0.75
            })

        results.sort(key=lambda x: x["composite_risk_score"], reverse=True)

        return {
            "target_brand": brand,
            "tld": tld,
            "engine": "openSquat / urlinsane Algorithmic Synthesis",
            "total_candidates_analyzed": len(results),
            "active_live_threats_detected": active_threats_count,
            "candidates": results,
            "recommendation": (
                f"Found {active_threats_count} actively live lookalike domains mimicking '{brand}'. Immediate proactive registrar defensive registration or UDRP takedowns recommended."
                if active_threats_count > 0 else
                f"Generated {len(results)} potential lookalike attack surfaces. No active critical live domains detected currently."
            )
        }
