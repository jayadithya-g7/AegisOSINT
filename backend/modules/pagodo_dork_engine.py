"""
AegisOSINT - Pagodo Passive Google Dork Automation Engine
Synthesized from opsdisk/pagodo, hhhrrrttt222111/Dorkify, and the Google Hacking Database (GHDB).

Key Capabilities:
- Generates 12 precision GHDB Google Dorks customized for brand impersonation defense.
- Uncovers rogue credential harvesting portals, exposed .env secrets, cloned landing pages, and paste leaks.
- Pre-compiles 1-click execution search URLs for Google, Bing, DuckDuckGo, and Yandex.
- Categorizes findings by tactical risk and adversary objective.
"""

import urllib.parse
from typing import List, Dict, Any, Optional

DORK_TEMPLATES = [
    {
        "category": "Credential Harvesters & Fake Logins",
        "template": '"{brand}" (inurl:login OR inurl:signin OR inurl:portal OR inurl:secure) -site:{legit}',
        "risk_level": "CRITICAL",
        "description": "Finds rogue websites hosting unauthorized login portals claiming to belong to the brand."
    },
    {
        "category": "Cloned Brand Assets & Title Mimicry",
        "template": 'intitle:"{brand}" (intitle:Login OR intitle:"Sign In" OR intitle:"Official") -site:{legit} -site:wikipedia.org -site:linkedin.com',
        "risk_level": "HIGH",
        "description": "Uncovers third-party domains copying exact brand HTML <title> strings."
    },
    {
        "category": "Social Engineering & Giveaway Scams",
        "template": '"{brand}" ("giveaway" OR "airdrop" OR "crypto bonus" OR "claim prize" OR "account suspended") -site:{legit}',
        "risk_level": "HIGH",
        "description": "Identifies active social engineering lures offering bogus promotions or warning of account suspension."
    },
    {
        "category": "Exposed Secrets & Environment Files",
        "template": '"{brand}" (filetype:env OR filetype:yml OR filetype:json OR filetype:conf) ("db_password" OR "api_key" OR "secret")',
        "risk_level": "CRITICAL",
        "description": "Locates exposed production database configuration files and API secrets containing brand references."
    },
    {
        "category": "Open Directory Phish-Kit Indexing",
        "template": 'site:{target} intitle:"Index of /"' if "{target}" else '"{brand}" intitle:"Index of /" (phish OR kit OR admin OR backup)',
        "risk_level": "HIGH",
        "description": "Finds unprotected open directory listings hosting unpackaged phishing kits or data dumps."
    },
    {
        "category": "Public Pastebin & Rentry Leaks",
        "template": '(site:pastebin.com OR site:rentry.co OR site:ghostbin.com OR site:justpaste.it) "{brand}"',
        "risk_level": "MEDIUM",
        "description": "Monitors public paste services for victim credential dumps, stealer logs, or threat actor notes."
    },
    {
        "category": "Compromised WordPress / CMS Phish Paths",
        "template": 'inurl:/wp-content/uploads/ "{brand}" inurl:login',
        "risk_level": "HIGH",
        "description": "Finds legitimate hacked WordPress sites where adversaries staged phishing kits in upload directories."
    },
    {
        "category": "Weaponized Spearphishing Documents",
        "template": '"{brand}" (filetype:pdf OR filetype:doc OR filetype:docx) ("urgent" OR "invoice overdue" OR "wire transfer")',
        "risk_level": "MEDIUM",
        "description": "Discovers malicious document lures designed for Business Email Compromise (BEC)."
    },
    {
        "category": "Database Dumps & Backups",
        "template": '"{brand}" (ext:sql OR ext:bak OR ext:dump OR ext:tar.gz) -site:{legit}',
        "risk_level": "CRITICAL",
        "description": "Scans for publicly indexable database backups and archive files associated with the brand."
    },
    {
        "category": "Subdomain Enumeration & Staging Backdoors",
        "template": 'site:*.{legit} -site:www.{legit} -site:m.{legit} -site:mail.{legit}',
        "risk_level": "MEDIUM",
        "description": "Finds unlinked subdomains, forgotten staging portals, or internal infrastructure."
    },
    {
        "category": "Brand Counterfeit & Unauthorized Resellers",
        "template": '"{brand}" ("replica" OR "cheap" OR "discount code" OR "counterfeit" OR "100% genuine") -site:{legit}',
        "risk_level": "MEDIUM",
        "description": "Identifies unauthorized storefronts peddling counterfeit goods using brand trademarks."
    },
    {
        "category": "Telegram / Discord Exfiltration Endpoints",
        "template": '"{brand}" intext:"api.telegram.org/bot" OR intext:"discord.com/api/webhooks" -site:{legit}',
        "risk_level": "CRITICAL",
        "description": "Locates source code repositories or exposed web pages with hardcoded C2 exfiltration endpoints."
    }
]


class PagodoDorkEngine:
    """
    Pagodo-style Automated Google Hacking Database (GHDB) Dorking Suite
    Tailored for proactive brand defense and fraud discovery.
    """

    def generate_dorks(self, brand_name: str, legitimate_domain: str = "", target_domain: str = "") -> Dict[str, Any]:
        """
        Synthesizes 12 custom search dorks with live URLs for Google, Bing, DuckDuckGo, and Yandex.
        """
        clean_brand = brand_name.strip()
        legit = legitimate_domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
        if not legit:
            legit = f"{clean_brand.lower().replace(' ', '')}.com"
        target = target_domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]

        dorks = []
        for t in DORK_TEMPLATES:
            # Format query string
            raw_dork = t["template"].format(brand=clean_brand, legit=legit, target=target or legit)
            query_enc = urllib.parse.quote_plus(raw_dork)

            dorks.append({
                "category": t["category"],
                "risk_level": t["risk_level"],
                "description": t["description"],
                "dork_syntax": raw_dork,
                "search_engines": {
                    "google": f"https://www.google.com/search?q={query_enc}",
                    "duckduckgo": f"https://duckduckgo.com/?q={query_enc}",
                    "bing": f"https://www.bing.com/search?q={query_enc}",
                    "yandex": f"https://yandex.com/search/?text={query_enc}"
                }
            })

        return {
            "brand": clean_brand,
            "legitimate_domain": legit,
            "target_domain": target or "N/A",
            "total_dorks": len(dorks),
            "dorks": dorks,
            "engine_reference": "opsdisk/pagodo & Google Hacking Database (GHDB)",
            "operational_guidance": "Click any search engine URL to execute passive OSINT reconnaissance without sending IP packets to the threat actor's infrastructure."
        }
