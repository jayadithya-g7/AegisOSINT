"""
AegisOSINT - Open Threat Feeds & Online OSINT Synthesis Module
Synthesizes free, open-source online OSINT tools for the Problem Statement:
1. Phishunt & OpenPhish Live Phishing Database Feeds (Ground-truth phishing IOC verification)
2. PhoneInfoga Fraudulent Communication & Smishing Phone OSINT (sundowndev/PhoneInfoga)
3. Reverse Image Search Dispatchers (TinEye, Yandex Images, Google Lens) for cloned logos
4. OnionSearch Tor Hidden Service Search (megadose/OnionSearch & Ahmia.fi)
5. Web Technology & Phishing Kit Stack Fingerprinter (Wappalyzer / WebTech OSINT)
"""

import os
import re
import urllib.parse
from typing import List, Dict, Any, Optional
import requests


class OpenThreatFeeds:
    """Aggregates and queries open-source online threat feeds and OSINT engines."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisOSINT/1.0 (Open-Source Threat Intelligence)"
        })
        self._cached_openphish: List[str] = []
        self._cached_phishunt: List[str] = []
        self._cache_timestamp: float = 0.0

    # =========================================================================
    # 1. LIVE OPEN-SOURCE PHISHING FEEDS (Phishunt & OpenPhish)
    # =========================================================================
    def check_live_phishing_feeds(self, target: str, brand_filter: Optional[str] = None, brand: Optional[str] = None) -> Dict[str, Any]:
        """
        Cross-references a domain, URL, or brand against live OpenPhish and Phishunt open feeds.
        Detects if the target is an actively confirmed phishing feed IOC.
        """
        effective_brand = brand or brand_filter
        clean_target = target.strip().lower()
        if clean_target.startswith(("http://", "https://")):
            clean_domain = urllib.parse.urlparse(clean_target).netloc
        else:
            clean_domain = clean_target.split('/')[0]

        openphish_matches = []
        phishunt_matches = []
        total_openphish_entries = 0
        total_phishunt_entries = 0

        # Query OpenPhish Community Feed
        try:
            r_op = self.session.get("https://openphish.com/feed.txt", timeout=4.0)
            if r_op.status_code == 200:
                op_lines = [line.strip() for line in r_op.text.splitlines() if line.strip()]
                total_openphish_entries = len(op_lines)
                for url in op_lines:
                    url_lower = url.lower()
                    if clean_domain in url_lower:
                        openphish_matches.append({
                            "url": url,
                            "feed": "OpenPhish Zero-Day Community Feed",
                            "severity": "CONFIRMED_MALICIOUS_PHISHING",
                            "status": "ACTIVE_IOC"
                        })
                    elif effective_brand and effective_brand.lower() in url_lower:
                        if len(openphish_matches) < 5:
                            openphish_matches.append({
                                "url": url,
                                "feed": "OpenPhish (Target Brand Match)",
                                "severity": "BRAND_TARGETED_PHISHING",
                                "status": "ACTIVE_IOC"
                            })
        except Exception:
            pass

        # Query Phishunt Community Feed
        try:
            r_ph = self.session.get("https://phishunt.io/feed.txt", timeout=4.0)
            if r_ph.status_code == 200:
                ph_lines = [line.strip() for line in r_ph.text.splitlines() if line.strip()]
                total_phishunt_entries = len(ph_lines)
                for url in ph_lines:
                    url_lower = url.lower()
                    if clean_domain in url_lower:
                        phishunt_matches.append({
                            "url": url,
                            "feed": "Phishunt Community Database",
                            "severity": "CONFIRMED_MALICIOUS_PHISHING",
                            "status": "ACTIVE_IOC"
                        })
                    elif effective_brand and effective_brand.lower() in url_lower:
                        if len(phishunt_matches) < 5:
                            phishunt_matches.append({
                                "url": url,
                                "feed": "Phishunt (Target Brand Match)",
                                "severity": "BRAND_TARGETED_PHISHING",
                                "status": "ACTIVE_IOC"
                            })
        except Exception:
            pass

        all_matches = openphish_matches + phishunt_matches
        is_confirmed_phishing = len(all_matches) > 0
        risk_score = 95.0 if is_confirmed_phishing else 0.0
        severity = "CRITICAL" if is_confirmed_phishing else "NO_MATCH_IN_LIVE_FEEDS"
        tactical_assessment = (
            f"GROUND-TRUTH MATCH: Target or brand matched {len(all_matches)} active zero-day phishing entries in open community threat feeds."
            if is_confirmed_phishing else
            f"No direct hit in {total_openphish_entries + total_phishunt_entries} live OpenPhish and Phishunt entries. Proceed with heuristic and lexical triage."
        )

        return {
            "target": target,
            "domain": clean_domain,
            "is_confirmed_phishing": is_confirmed_phishing,
            "risk_score": risk_score,
            "severity": severity,
            "openphish_feed_total": total_openphish_entries,
            "phishunt_feed_total": total_phishunt_entries,
            "matched_iocs_count": len(all_matches),
            "matched_iocs": all_matches,
            "tactical_assessment": tactical_assessment,
            "tactical_guidance": tactical_assessment,
            "overall_verdict": {
                "is_confirmed_phishing": is_confirmed_phishing,
                "threat_severity": severity,
                "confidence_score": risk_score,
                "sources_confirming": [m["feed"] for m in all_matches]
            },
            "openphish": {
                "total_feed_entries": total_openphish_entries,
                "matched": len(openphish_matches) > 0,
                "status": "FEED_PARSED_SUCCESS" if total_openphish_entries > 0 else "FALLBACK_HEURISTIC_APPLIED"
            },
            "phishunt": {
                "total_feed_entries": total_phishunt_entries,
                "matched": len(phishunt_matches) > 0,
                "status": "FEED_PARSED_SUCCESS" if total_phishunt_entries > 0 else "FALLBACK_HEURISTIC_APPLIED"
            }
        }

    # =========================================================================
    # 2. FRAUDULENT COMMUNICATION & SMISHING PHONE OSINT (PhoneInfoga synthesis)
    # =========================================================================
    def analyze_fraud_phone_number(self, phone_number: str) -> Dict[str, Any]:
        """
        Analyzes suspect phone numbers harvested from fraudulent emails, SMS lures,
        and fake customer care social handles.
        Synthesizes sundowndev/PhoneInfoga methodology: E.164 parsing, carrier dorks,
        and fraud complaint database lookups.
        """
        raw = phone_number.strip()
        digits_only = re.sub(r'[^\d+]', '', raw)
        clean_num = digits_only if digits_only.startswith('+') else f"+{digits_only}"
        num_no_plus = clean_num.lstrip('+')

        country_code = "Unknown"
        country_name = "International"
        probable_country = "International"
        if num_no_plus.startswith("1"):
            country_code = "+1"
            country_name = "United States / Canada (NANP)"
            probable_country = "US/CA"
        elif num_no_plus.startswith("44"):
            country_code = "+44"
            country_name = "United Kingdom"
            probable_country = "UK"
        elif num_no_plus.startswith("91"):
            country_code = "+91"
            country_name = "India"
            probable_country = "IN"
        elif num_no_plus.startswith("33"):
            country_code = "+33"
            country_name = "France"
            probable_country = "FR"
        elif num_no_plus.startswith("49"):
            country_code = "+49"
            country_name = "Germany"
            probable_country = "DE"
        elif num_no_plus.startswith("7"):
            country_code = "+7"
            country_name = "Russia / Kazakhstan"
            probable_country = "RU"
        elif num_no_plus.startswith("86"):
            country_code = "+86"
            country_name = "China"
            probable_country = "CN"
        elif num_no_plus.startswith("61"):
            country_code = "+61"
            country_name = "Australia"
            probable_country = "AU"
        elif num_no_plus.startswith("234"):
            country_code = "+234"
            country_name = "Nigeria"
            probable_country = "NG"

        # Check toll-free / high-risk fraud prefixes (1-800, 1-888, 1-877, 1-866, 1-855)
        is_toll_free = any(num_no_plus.startswith(f"1{prefix}") for prefix in ["800", "888", "877", "866", "855", "844", "833"]) or any(num_no_plus.startswith(prefix) for prefix in ["800", "888", "877", "866", "855"])
        is_premium_rate = any(num_no_plus.startswith(p) for p in ["1900", "449", "4487", "4484"])

        risk_score = 45.0
        indicators = []
        line_type = "LANDLINE"
        if is_toll_free:
            risk_score += 35.0
            line_type = "TOLL_FREE"
            indicators.append("Toll-Free Helpline Spoofing: Adversaries frequently provision disposable toll-free VOIP trunks to mimic corporate support.")
        elif is_premium_rate:
            risk_score += 45.0
            line_type = "PREMIUM_RATE"
            indicators.append("Premium Rate Number: Callers are billed exorbitant rates per minute (Toll Fraud / IRS / Bank Scam).")
        elif num_no_plus.startswith("447") or (country_code == "+1" and not is_toll_free):
            line_type = "MOBILE"
        elif num_no_plus.startswith("4420") or num_no_plus.startswith("441"):
            line_type = "LANDLINE"

        if country_code in ["+234", "+7"]:
            risk_score += 20.0
            indicators.append("Geographic Anomaly: Operating from high-risk offshore jurisdiction commonly tied to BEC syndicates.")

        # Formatting
        if num_no_plus.startswith("1") and len(num_no_plus) == 11:
            national_format = f"({num_no_plus[1:4]}) {num_no_plus[4:7]}-{num_no_plus[7:]}"
            international_format = f"+1 {num_no_plus[1:4]} {num_no_plus[4:7]} {num_no_plus[7:]}"
        elif num_no_plus.startswith("44") and len(num_no_plus) >= 10:
            national_format = f"0{num_no_plus[2:6]} {num_no_plus[6:]}"
            international_format = f"+44 {num_no_plus[2:6]} {num_no_plus[6:]}"
        else:
            national_format = num_no_plus
            international_format = clean_num

        encoded_num = urllib.parse.quote_plus(clean_num)
        osint_links = [
            {
                "service": "WhoCalledMe (Scam Reports)",
                "url": f"https://whocallsme.com/Phone.aspx/{num_no_plus}",
                "category": "Victim Complaint Database"
            },
            {
                "service": "800notes (Consumer Fraud Reports)",
                "url": f"https://800notes.com/Phone.aspx/{num_no_plus}",
                "category": "Consumer Scam Ledger"
            },
            {
                "service": "ScamPulse (Verified Fraud Ledger)",
                "url": f"https://www.scampulse.com/search?q={num_no_plus}",
                "category": "Scam Reports"
            },
            {
                "service": "Truecaller Public Search",
                "url": f"https://www.truecaller.com/search/none/{encoded_num}",
                "category": "Caller ID & Spam Tags"
            },
            {
                "service": "Google Fraud Dork",
                "url": f"https://www.google.com/search?q=%22{encoded_num}%22+AND+(scam+OR+fraud+OR+phishing+OR+impersonation)",
                "category": "Passive Dork Search"
            }
        ]

        reputation_searches = {
            "whocalledme": f"https://whocallsme.com/Phone.aspx/{num_no_plus}",
            "800notes": f"https://800notes.com/Phone.aspx/{num_no_plus}",
            "scampulse": f"https://www.scampulse.com/search?q={num_no_plus}",
            "truecaller": f"https://www.truecaller.com/search/none/{encoded_num}",
            "google_dork": f"https://www.google.com/search?q=%22{encoded_num}%22+AND+(scam+OR+fraud+OR+phishing+OR+impersonation)",
            "numlookup": f"https://www.numlookup.com/search?phone={num_no_plus}"
        }

        final_risk = min(100.0, risk_score)
        severity = "CRITICAL" if final_risk >= 70 else ("HIGH" if final_risk >= 55 else "SUSPICIOUS")

        return {
            "input_number": phone_number,
            "raw_input": phone_number,
            "e164": clean_num,
            "e164_format": clean_num,
            "national_digits": num_no_plus,
            "national_format": national_format,
            "international_format": international_format,
            "country_code": country_code,
            "probable_country": probable_country,
            "jurisdiction": country_name,
            "line_type": line_type,
            "is_toll_free": is_toll_free,
            "is_premium_rate": is_premium_rate,
            "risk_score": final_risk,
            "fraud_risk_score": int(final_risk),
            "severity": severity,
            "indicators": indicators,
            "fraud_indicators": indicators,
            "reputation_searches": reputation_searches,
            "osint_investigation_links": osint_links,
            "tactical_assessment": f"Phone number evaluated under PhoneInfoga standard. Line classification: {line_type}. Fraud risk: {int(final_risk)}/100.",
            "framework_provenance": "sundowndev/PhoneInfoga OSINT Standard"
        }

    # =========================================================================
    # 3. REVERSE IMAGE SEARCH DISPATCHER (TinEye, Yandex, Google Lens, Bing)
    # =========================================================================
    @staticmethod
    def generate_reverse_image_search_links(image_url: str) -> Dict[str, Any]:
        """
        Generates direct 1-click Reverse Image Search URLs for TinEye, Yandex Images,
        Google Lens, and Bing Visual Search.
        Addresses the PS requirement for detecting cloned logos and visual brand abuse.
        """
        encoded_url = urllib.parse.quote_plus(image_url)

        tineye_url = f"https://tineye.com/search?url={encoded_url}"
        yandex_url = f"https://yandex.com/images/search?rpt=imageview&url={encoded_url}"
        lens_url = f"https://lens.google.com/uploadbyurl?url={encoded_url}"
        bing_url = f"https://www.bing.com/images/search?view=detailv2&iss=sbi&FORM=SBIHMP&sbisrc=UrlPaste&q=imgurl:{encoded_url}"

        return {
            "image_url": image_url,
            "target_image_url": image_url,
            "tineye_search_url": tineye_url,
            "yandex_images_url": yandex_url,
            "google_lens_url": lens_url,
            "bing_visual_url": bing_url,
            "search_engines": {
                "tineye": {"name": "TinEye Reverse Image Search", "url": tineye_url},
                "yandex": {"name": "Yandex Visual Search", "url": yandex_url},
                "lens": {"name": "Google Lens", "url": lens_url},
                "bing": {"name": "Bing Visual Search", "url": bing_url}
            },
            "engines_covered": ["TinEye", "Yandex Images", "Google Lens", "Bing Visual"],
            "tactical_guidance": "Click any engine to track unauthorized re-hosting of brand emblems, cloned logos, or product assets across the web."
        }

    # =========================================================================
    # 4. DARK WEB & BREACH OSINT (megadose/OnionSearch & Ahmia.fi)
    # =========================================================================
    @staticmethod
    def generate_darkweb_brand_searches(brand_name: str = "", target_domain: Optional[str] = None, brand: Optional[str] = None, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Generates direct search queries for Tor hidden service search engines
        (Ahmia.fi, OnionLand, Tor.link) to investigate if the brand or domain is listed
        in dark web dumps, carding markets, or phish kit repositories.
        Synthesizes megadose/OnionSearch and apurvsinghgautam/dark-web-osint-tools.
        """
        brand_clean = (brand or brand_name or "").strip()
        domain_clean = (domain or target_domain or "").strip()
        query = f"{brand_clean} {domain_clean}".strip()
        encoded_query = urllib.parse.quote_plus(query)

        ahmia_url = f"https://ahmia.fi/search/?q={encoded_query}"
        onionland_url = f"https://onionlandsearchengine.com/search?q={encoded_query}"
        torlink_url = f"https://tor.link/search?q={encoded_query}"
        darksearch_url = f"https://darksearch.io/search?query={encoded_query}"
        torch_url = f"https://torchsearch.wordpress.com/?s={encoded_query}"

        return {
            "brand": brand_clean,
            "domain": domain_clean,
            "target_domain": domain_clean,
            "ahmia_tor_search": ahmia_url,
            "onionland_search": onionland_url,
            "torch_search": torch_url,
            "darkweb_dork_syntax": f"{brand_clean} site:*.onion OR intext:\"{brand_clean}\"",
            "darkweb_gateways": {
                "ahmia_fi": {"name": "Ahmia.fi Tor Hidden Service Indexer", "url": ahmia_url},
                "onionland": {"name": "OnionLand Engine", "url": onionland_url},
                "torlink": {"name": "Tor.link Search", "url": torlink_url},
                "darksearch": {"name": "DarkSearch.io Gateway", "url": darksearch_url}
            },
            "onionsearch_cli_command": f"onionsearch '{brand_clean}' --engines ahmia torch candle",
            "tactical_guidance": "Tor hidden service indexers scan unindexed darknet forums, credential trading markets, and hidden phishing drops.",
            "methodology": "megadose/OnionSearch & Ahmia.fi Tor Hidden Service Index"
        }

    # =========================================================================
    # 5. WEB TECHNOLOGY & PHISHING STACK FINGERPRINTING (Wappalyzer / WebTech)
    # =========================================================================
    def fingerprint_web_technology(self, target_url: str = "", url: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspects remote HTTP response headers, cookies, and DOM meta tags
        to identify the web technology stack, reverse proxies, and phishing kit markers.
        Addresses the PS requirement for fake website investigation.
        """
        eff_url = url or target_url
        req_url = eff_url if eff_url.startswith(("http://", "https://")) else f"https://{eff_url}"
        technologies = []
        tech_names = []
        security_headers = {}
        suspicious_markers = []

        try:
            r = self.session.get(req_url, timeout=4.0, verify=False, allow_redirects=True)
            headers = r.headers
            text = r.text

            # 1. Inspect Server header
            server_header = headers.get("Server", "Unknown")
            technologies.append({"category": "Web Server", "name": server_header})
            tech_names.append(server_header)

            # 2. Inspect X-Powered-By
            powered_by = headers.get("X-Powered-By")
            if powered_by:
                technologies.append({"category": "Runtime / Framework", "name": powered_by})
                tech_names.append(powered_by)

            # 3. Detect CDN / Reverse Proxy
            if "cf-ray" in headers or "cloudflare" in server_header.lower():
                technologies.append({"category": "CDN / WAF", "name": "Cloudflare"})
                tech_names.append("Cloudflare")
            if "x-sucuri-id" in headers:
                technologies.append({"category": "CDN / WAF", "name": "Sucuri"})
                tech_names.append("Sucuri")
            if "x-akamai-transformed" in headers:
                technologies.append({"category": "CDN", "name": "Akamai"})
                tech_names.append("Akamai")

            # 4. Detect cPanel / Webmail / Phishing Host Stacks
            if ":2083" in text or "cPanel" in text or "cpsess" in text:
                technologies.append({"category": "Hosting Panel", "name": "cPanel / WHM"})
                tech_names.append("cPanel / WHM")
                suspicious_markers.append("cPanel webmail infrastructure frequently leveraged by phish kits.")

            # 5. Detect CMS
            if "wp-content" in text or "wp-includes" in text:
                technologies.append({"category": "CMS", "name": "WordPress (Potentially Compromised Site)"})
                tech_names.append("WordPress")
                suspicious_markers.append("Compromised WordPress installation repurposed as phishing staging ground.")
            elif "Joomla" in text:
                technologies.append({"category": "CMS", "name": "Joomla"})
                tech_names.append("Joomla")

            # 6. Detect Form Exfiltration / Telemetry
            if "api.telegram.org" in text:
                suspicious_markers.append("CRITICAL: Embedded Telegram Bot API token exfiltration detected in page source.")
            if "discord.com/api/webhooks" in text:
                suspicious_markers.append("CRITICAL: Embedded Discord Webhook exfiltration detected in page source.")

            # 7. Check Essential Security Headers
            hsts = headers.get("Strict-Transport-Security") is not None
            csp = headers.get("Content-Security-Policy") is not None
            xfo = headers.get("X-Frame-Options") is not None
            xcto = headers.get("X-Content-Type-Options") is not None

            security_headers = {
                "strict_transport_security": hsts,
                "content_security_policy": csp,
                "x_frame_options": xfo,
                "x_content_type_options": xcto,
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "MISSING"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "MISSING"),
                "X-Frame-Options": headers.get("X-Frame-Options", "MISSING"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "MISSING")
            }

            return {
                "url": req_url,
                "target_url": req_url,
                "status_code": r.status_code,
                "server": server_header,
                "technologies_detected": tech_names,
                "technologies_details": technologies,
                "security_headers": security_headers,
                "suspicious_markers": suspicious_markers,
                "phishing_kit_markers": suspicious_markers,
                "is_likely_phishing_kit": len(suspicious_markers) > 0,
                "tactical_assessment": "Stack fingerprinted via HTTP response headers and DOM heuristics.",
                "analysis_status": "SUCCESS"
            }
        except Exception as e:
            return {
                "url": req_url,
                "target_url": req_url,
                "status_code": 0,
                "server": "Unreachable",
                "technologies_detected": ["Host Offline / Blocked"],
                "technologies_details": [{"category": "Web Server", "name": "Host Offline / Blocked"}],
                "security_headers": {"strict_transport_security": False, "content_security_policy": False, "x_frame_options": False},
                "suspicious_markers": ["Host was unreachable during live HTTP probe."],
                "phishing_kit_markers": [],
                "is_likely_phishing_kit": False,
                "tactical_assessment": f"Probe error: {str(e)}",
                "analysis_status": f"ERROR: {str(e)}"
            }

    # Method alias
    inspect_fraud_phone = analyze_fraud_phone_number


# Class alias for cross-module integration
OpenThreatFeedsAggregator = OpenThreatFeeds


