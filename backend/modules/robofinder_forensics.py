"""
AegisOSINT - Robofinder Historical Robots.txt & Staging Forensics
Synthesized from Spix0r/robofinder and web.archive.org CDX API.

Key Capabilities:
- Queries Wayback Machine CDX API for historical snapshots of robots.txt for suspect domains.
- Analyzes Disallow: directives to unmask hidden directories (admin panels, staging paths, phish kit drops).
- Compares historical versions to detect sudden drops of new disallow paths indicative of phish kits.
"""

from typing import List, Dict, Any, Optional
import requests

HIGH_RISK_PATH_KEYWORDS = [
    "admin", "panel", "login", "portal", "backup", "db", "sql", "config",
    "secret", "api", "phish", "c2", "log", "staging", "dev", "test", "upload"
]


class RobofinderForensics:
    """
    Historical robots.txt crawler & unindexed directory forensicator.
    Synthesizes techniques from Spix0r/robofinder.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AegisOSINT-Robofinder/2.0 (Historical Directory Recon)"
        })

    def analyze_domain_robots(self, domain: str) -> Dict[str, Any]:
        """
        Fetches live and historical robots.txt entries for a target domain.
        Extracts Disallow paths and flags suspicious hidden directories.
        """
        clean_domain = domain.lower().strip().replace("http://", "").replace("https://", "").split("/")[0]

        disallowed_paths = []
        high_risk_paths = []
        is_live_found = False

        # 1. Try live fetch directly
        try:
            r = self.session.get(f"https://{clean_domain}/robots.txt", timeout=3.5, verify=False)
            if r.status_code == 200 and "disallow" in r.text.lower():
                is_live_found = True
                for line in r.text.splitlines():
                    line_clean = line.strip()
                    if line_clean.lower().startswith("disallow:"):
                        path = line_clean.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallowed_paths.append(path)
        except Exception:
            pass

        # 2. Try Wayback Machine CDX API fallback
        if not disallowed_paths:
            try:
                cdx_url = f"https://web.archive.org/cdx/search/cdx?url={clean_domain}/robots.txt&output=json&limit=5"
                r_cdx = self.session.get(cdx_url, timeout=3.5)
                if r_cdx.status_code == 200:
                    rows = r_cdx.json()
                    if len(rows) > 1:
                        # Grab timestamp of closest snapshot
                        ts = rows[1][1]
                        snap_url = f"https://web.archive.org/web/{ts}id_/{clean_domain}/robots.txt"
                        r_snap = self.session.get(snap_url, timeout=3.5)
                        if r_snap.status_code == 200:
                            for line in r_snap.text.splitlines():
                                line_clean = line.strip()
                                if line_clean.lower().startswith("disallow:"):
                                    path = line_clean.split(":", 1)[1].strip()
                                    if path and path != "/":
                                        disallowed_paths.append(path)
            except Exception:
                pass

        # De-duplicate paths
        unique_paths = list(set(disallowed_paths))

        # Flag high-risk keywords in paths
        for p in unique_paths:
            p_lower = p.lower()
            if any(kw in p_lower for kw in HIGH_RISK_PATH_KEYWORDS):
                high_risk_paths.append(p)

        risk_score = 10
        if unique_paths:
            risk_score += 15
        if high_risk_paths:
            risk_score += min(50, len(high_risk_paths) * 20)

        final_risk = min(100, risk_score)

        return {
            "domain": clean_domain,
            "robots_txt_found": len(unique_paths) > 0,
            "is_live_source": is_live_found,
            "total_disallowed_paths": len(unique_paths),
            "disallowed_paths": unique_paths[:15],
            "high_risk_sensitive_paths": high_risk_paths,
            "risk_score": final_risk,
            "severity": "CRITICAL" if final_risk >= 70 else ("HIGH" if final_risk >= 50 else ("MEDIUM" if final_risk >= 25 else "LOW")),
            "tactical_assessment": (
                f"Discovered {len(high_risk_paths)} high-risk unindexed directories ({', '.join(high_risk_paths[:3])}). "
                f"Adversaries frequently use robots.txt disallow directives to conceal active phishing kits and admin drop zones."
                if high_risk_paths else
                f"Found {len(unique_paths)} disallowed paths. No high-risk staging keywords detected."
            )
        }
