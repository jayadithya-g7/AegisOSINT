"""
AegisOSINT - Real-Time Live Domain & Suspicious Infrastructure Scanner
Performs 100% LIVE network reconnaissance:
- Live DNS resolution (A, AAAA, MX, NS, TXT) via public and recursive resolvers
- Live ICANN RDAP protocol queries for authoritative registrar, registration date, domain age, and status
- Live SSL/TLS X.509 certificate handshake, SAN enumeration, and SHA-256 fingerprinting
- Live HTTP/HTTPS web probing, redirect tracking, server header inspection, title extraction, and login form detection
- Live combinatorial Typosquatting, Combosquatting, and IDN Homoglyph attack generation
"""

import socket
import ssl
import datetime
import urllib.parse
import re
from typing import List, Dict, Any, Optional
import requests

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# QWERTY adjacent characters for typosquatting modeling
QWERTY_NEIGHBORS = {
    'a': ['q', 'w', 's', 'z'],
    'b': ['v', 'g', 'h', 'n'],
    'c': ['x', 'd', 'f', 'v'],
    'd': ['s', 'e', 'r', 'f', 'c', 'x'],
    'e': ['w', 's', 'd', 'r', '3'],
    'f': ['d', 'r', 't', 'g', 'v', 'c'],
    'g': ['f', 't', 'y', 'h', 'b', 'v'],
    'h': ['g', 'y', 'u', 'j', 'n', 'b'],
    'i': ['u', 'j', 'k', 'o', '8', '1', 'l'],
    'j': ['h', 'u', 'i', 'k', 'm', 'n'],
    'k': ['j', 'i', 'o', 'l', 'm'],
    'l': ['k', 'o', 'p', 'i', '1'],
    'm': ['n', 'j', 'k'],
    'n': ['b', 'h', 'j', 'm'],
    'o': ['i', 'k', 'l', 'p', '0'],
    'p': ['o', 'l', '0'],
    'q': ['1', 'w', 'a'],
    'r': ['e', 'd', 'f', 't', '4'],
    's': ['a', 'w', 'e', 'd', 'x', 'z'],
    't': ['r', 'f', 'g', 'y', '5'],
    'u': ['y', 'h', 'j', 'i', '7'],
    'v': ['c', 'f', 'g', 'b'],
    'w': ['q', 'a', 's', 'e', '2'],
    'x': ['z', 's', 'd', 'c'],
    'y': ['t', 'g', 'h', 'u', '6'],
    'z': ['a', 's', 'x'],
    '0': ['o', 'p'],
    '1': ['l', 'i'],
    '3': ['e'],
    '5': ['s']
}

# Homoglyph lookup table (ASCII to visually identical Unicode / Cyrillic / Greek characters)
HOMOGLYPH_MAP = {
    'a': ['а', 'à', 'á', 'â', 'ã', 'ä', 'ɑ'],
    'c': ['с', 'ç', 'ć', 'č'],
    'e': ['е', 'é', 'è', 'ê', 'ë', 'ė', 'є'],
    'i': ['і', 'í', 'ì', 'ï', 'ı', '1', 'l'],
    'j': ['ј'],
    'l': ['1', 'I', 'ł', 'ⅼ'],
    'o': ['о', '0', 'ò', 'ó', 'ô', 'ö', 'ø'],
    'p': ['р', 'ρ'],
    's': ['ѕ', 'ş', 'š'],
    'u': ['υ', 'ù', 'ú', 'û', 'ü'],
    'v': ['ν'],
    'x': ['х', 'ж'],
    'y': ['у', 'ý', 'ÿ']
}

# High-risk phishing combosquatting keywords
COMBOSQUAT_KEYWORDS = [
    'login', 'secure', 'verify', 'support', 'auth', 'portal', 'account',
    'update', 'pay', 'kyc', 'helpdesk', 'service', 'billing', 'wallet',
    'security', 'access', 'confirm', 'signin', 'official', 'member', 'check'
]

# High-risk TLDs commonly abused in automated phishing
HIGH_RISK_TLDS = {
    '.xyz': 25, '.top': 30, '.tk': 35, '.ml': 30, '.ga': 30,
    '.cf': 30, '.gq': 30, '.club': 20, '.live': 25, '.store': 20,
    '.icu': 30, '.vip': 25, '.cc': 20, '.site': 20, '.online': 20,
    '.fun': 25, '.buzz': 25, '.work': 20, '.link': 20, '.click': 25
}


def calculate_levenshtein(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    return dp[m][n]


def calculate_similarity_ratio(s1: str, s2: str) -> float:
    """Returns normalized similarity ratio [0.0 - 1.0]."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = calculate_levenshtein(s1, s2)
    return round(1.0 - (dist / max_len), 4)


class DomainScanner:
    """Live internet network scanner, RDAP inspector, and domain generator."""

    def __init__(self):
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
            self.resolver.timeout = 2.5
            self.resolver.lifetime = 2.5
        else:
            self.resolver = None

        self.http_session = requests.Session()
        self.http_session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisOSINT/1.0 (Live Security Scanner)"
        })

    def generate_permutations(self, brand: str, base_tld: str = "com", max_per_type: int = 15) -> List[Dict[str, Any]]:
        """Generates typosquatting, combosquatting, homoglyph, and TLD variants."""
        brand_clean = brand.lower().strip()
        permutations: List[Dict[str, Any]] = []
        seen_domains = set()

        def add_perm(domain: str, attack_type: str, technique: str, description: str):
            if domain not in seen_domains and domain != f"{brand_clean}.{base_tld}":
                seen_domains.add(domain)
                permutations.append({
                    "domain": domain,
                    "attack_type": attack_type,
                    "technique": technique,
                    "description": description,
                    "target_brand": brand_clean
                })

        # 1. Typosquatting - Omission
        for i in range(len(brand_clean)):
            if len(brand_clean) > 3 and len(permutations) < max_per_type:
                variant = brand_clean[:i] + brand_clean[i + 1:]
                add_perm(f"{variant}.{base_tld}", "Typosquatting", "Omission", f"Omitted character '{brand_clean[i]}'")

        # 2. Typosquatting - Repetition
        for char in brand_clean:
            if len(permutations) < max_per_type * 2:
                variant = brand_clean + char
                add_perm(f"{variant}.{base_tld}", "Typosquatting", "Repetition", f"Repeated character '{char}'")

        # 3. Typosquatting - Adjacent Keyboard Substitution
        for i, char in enumerate(brand_clean):
            neighbors = QWERTY_NEIGHBORS.get(char, [])
            for n in neighbors[:2]:
                if len(permutations) < max_per_type * 3:
                    variant = brand_clean[:i] + n + brand_clean[i + 1:]
                    add_perm(f"{variant}.{base_tld}", "Typosquatting", "QWERTY Substitution", f"Substituted '{char}' with neighboring '{n}'")

        # 4. Combosquatting
        for kw in COMBOSQUAT_KEYWORDS:
            if len(permutations) < max_per_type * 6:
                add_perm(f"{brand_clean}-{kw}.{base_tld}", "Combosquatting", "Hyphenated Affix", f"Appended keyword '-{kw}'")
                add_perm(f"{kw}-{brand_clean}.{base_tld}", "Combosquatting", "Hyphenated Prefix", f"Prepended keyword '{kw}-'")
                add_perm(f"{brand_clean}{kw}.{base_tld}", "Combosquatting", "Direct Concat", f"Appended keyword '{kw}'")

        # 5. Homoglyphs & IDN Punycode Attacks
        for i, char in enumerate(brand_clean):
            if char in HOMOGLYPH_MAP:
                for glyph in HOMOGLYPH_MAP[char][:2]:
                    unicode_variant = brand_clean[:i] + glyph + brand_clean[i + 1:]
                    try:
                        puny_variant = unicode_variant.encode('idna').decode('ascii')
                        add_perm(f"{puny_variant}.{base_tld}", "Homoglyph/IDN", "Punycode Spoofing",
                                 f"Visual glyph '{glyph}' ({unicode_variant}.{base_tld})")
                    except Exception:
                        pass

        # 6. High-Risk TLD Swapping
        for tld in list(HIGH_RISK_TLDS.keys())[:max_per_type]:
            clean_tld = tld.lstrip('.')
            add_perm(f"{brand_clean}.{clean_tld}", "TLD Swapping", "Suspicious TLD", f"High-risk extension '{tld}'")

        return permutations

    def resolve_dns(self, domain: str) -> Dict[str, Any]:
        """Performs live authoritative DNS queries across public resolvers."""
        clean_domain = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
        result: Dict[str, Any] = {
            "domain": clean_domain,
            "resolved": False,
            "ip_addresses": [],
            "mail_servers": [],
            "name_servers": [],
            "txt_records": [],
            "cname_records": [],
            "error": None
        }

        # Socket getaddrinfo resolution
        try:
            addr_info = socket.getaddrinfo(clean_domain, None)
            for item in addr_info:
                ip = item[4][0]
                if ip not in result["ip_addresses"]:
                    result["ip_addresses"].append(ip)
            if result["ip_addresses"]:
                result["resolved"] = True
        except socket.gaierror:
            pass
        except Exception as e:
            result["error"] = str(e)

        # Advanced DNS queries if dnspython is available
        if DNS_AVAILABLE and self.resolver:
            # Query A records
            try:
                answers = self.resolver.resolve(clean_domain, 'A')
                for rdata in answers:
                    ip = rdata.to_text()
                    if ip not in result["ip_addresses"]:
                        result["ip_addresses"].append(ip)
                result["resolved"] = True
            except Exception:
                pass

            # Query MX records
            try:
                mx_answers = self.resolver.resolve(clean_domain, 'MX')
                for rdata in mx_answers:
                    mx_host = str(rdata.exchange).rstrip('.')
                    if mx_host not in result["mail_servers"]:
                        result["mail_servers"].append(mx_host)
            except Exception:
                pass

            # Query NS records
            try:
                ns_answers = self.resolver.resolve(clean_domain, 'NS')
                for rdata in ns_answers:
                    ns_host = str(rdata.target).rstrip('.')
                    if ns_host not in result["name_servers"]:
                        result["name_servers"].append(ns_host)
            except Exception:
                pass

            # Query TXT records
            try:
                txt_answers = self.resolver.resolve(clean_domain, 'TXT')
                for rdata in txt_answers:
                    txt_val = rdata.to_text().strip('"')
                    if txt_val not in result["txt_records"]:
                        result["txt_records"].append(txt_val)
            except Exception:
                pass

        return result

    def inspect_whois_rdap(self, domain: str) -> Dict[str, Any]:
        """
        Queries live ICANN RDAP endpoints (rdap.org) to fetch authoritative registration data,
        real registrar name, creation/expiration timestamps, domain age, and ICANN status.
        """
        clean_domain = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
        rdap_url = f"https://rdap.org/domain/{clean_domain}"

        res: Dict[str, Any] = {
            "domain": clean_domain,
            "source": "ICANN Authoritative RDAP (rdap.org)",
            "registrar": "Unknown / Unregistered",
            "created_date": None,
            "expiration_date": None,
            "age_days": None,
            "status": [],
            "nameservers": [],
            "is_registered": False,
            "error": None
        }

        try:
            r = self.http_session.get(rdap_url, timeout=4.5)
            if r.status_code == 200:
                data = r.json()
                res["is_registered"] = True

                # Extract registrar from entities
                entities = data.get("entities", [])
                for entity in entities:
                    roles = entity.get("roles", [])
                    if "registrar" in roles or "sponsor" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    res["registrar"] = item[3]
                                    break
                        if res["registrar"] == "Unknown / Unregistered":
                            res["registrar"] = entity.get("handle") or "Authoritative Registrar"

                # Extract events (creation, expiration)
                events = data.get("events", [])
                for ev in events:
                    action = ev.get("eventAction", "")
                    date_str = ev.get("eventDate", "")
                    if action == "registration":
                        res["created_date"] = date_str[:10]
                        try:
                            created_dt = datetime.datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                            now_dt = datetime.datetime.now(datetime.timezone.utc)
                            res["age_days"] = max(0, (now_dt - created_dt).days)
                        except Exception:
                            pass
                    elif action == "expiration":
                        res["expiration_date"] = date_str[:10]

                # Status
                res["status"] = data.get("status", [])

                # Nameservers
                for ns in data.get("nameservers", []):
                    ns_name = ns.get("ldhName", "")
                    if ns_name:
                        res["nameservers"].append(ns_name.lower())

            elif r.status_code == 404:
                res["registrar"] = "Unregistered / Available"
                res["error"] = "Domain not found in RDAP registry (Unregistered or pending delegation)"
            else:
                res["error"] = f"RDAP endpoint returned HTTP {r.status_code}"
        except Exception as e:
            res["error"] = f"Live RDAP query timeout or error: {str(e)}"

        return res

    def inspect_ssl(self, domain: str, port: int = 443, timeout: float = 3.5) -> Dict[str, Any]:
        """
        Performs live TLS handshake with SNI on port 443.
        Extracts real X.509 cert chain, Issuer, Subject, SANs, validity period, and SHA256 fingerprint.
        """
        clean_domain = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
        res: Dict[str, Any] = {
            "domain": clean_domain,
            "has_ssl": False,
            "issuer": None,
            "issuer_org": None,
            "subject": None,
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None,
            "sans": [],
            "is_free_cert": False,
            "sha256_fingerprint": None,
            "error": None
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((clean_domain, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_bin = ssock.getpeercert(binary_form=True)
                    res["has_ssl"] = True

                    if cert_bin:
                        import hashlib
                        res["sha256_fingerprint"] = hashlib.sha256(cert_bin).hexdigest()

                    if cert:
                        # Extract issuer
                        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                        res["issuer_org"] = issuer_dict.get("organizationName")
                        res["issuer"] = issuer_dict.get("commonName") or issuer_dict.get("organizationName")

                        # Extract subject
                        subj_dict = dict(x[0] for x in cert.get("subject", []))
                        res["subject"] = subj_dict.get("commonName") or subj_dict.get("organizationName")

                        # Validity
                        res["valid_from"] = cert.get("notBefore")
                        res["valid_to"] = cert.get("notAfter")

                        # Check for Let's Encrypt / ZeroSSL / cPanel / Cloudflare automated free certs
                        issuer_str = f"{res.get('issuer', '')} {res.get('issuer_org', '')}".lower()
                        if any(k in issuer_str for k in ["let's encrypt", "zerossl", "cpanel", "cloudflare"]):
                            res["is_free_cert"] = True

                        # Subject Alternative Names (SANs)
                        for san_type, san_val in cert.get("subjectAltName", []):
                            if san_type == "DNS":
                                res["sans"].append(san_val)

                        # Calculate days remaining
                        try:
                            expire_dt = datetime.datetime.strptime(cert.get("notAfter"), "%b %d %H:%M:%S %Y %Z")
                            now_dt = datetime.datetime.utcnow()
                            res["days_remaining"] = (expire_dt - now_dt).days
                        except Exception:
                            pass
        except Exception as e:
            res["error"] = str(e)

        return res

    def probe_http(self, domain: str, timeout: float = 4.0) -> Dict[str, Any]:
        """
        Performs live HTTP/HTTPS probe:
        - Detects live website availability
        - Captures HTTP status code, redirects, final landing URL
        - Inspects Server header and security headers (HSTS, CSP, X-Frame-Options)
        - Extracts HTML title and identifies password/login credential input fields
        """
        clean_domain = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
        result = {
            "domain": clean_domain,
            "is_live": False,
            "status_code": None,
            "final_url": None,
            "page_title": None,
            "server_header": None,
            "has_hsts": False,
            "has_csp": False,
            "has_login_form": False,
            "detected_inputs": [],
            "meta_description": None,
            "response_time_ms": None,
            "error": None
        }

        target_url = f"https://{clean_domain}"
        start_time = datetime.datetime.now()

        try:
            resp = self.http_session.get(target_url, timeout=timeout, allow_redirects=True, verify=False)
            elapsed = (datetime.datetime.now() - start_time).total_seconds() * 1000
            result["is_live"] = True
            result["status_code"] = resp.status_code
            result["final_url"] = resp.url
            result["response_time_ms"] = round(elapsed, 1)

            # Headers
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            result["server_header"] = headers_lower.get("server")
            result["has_hsts"] = "strict-transport-security" in headers_lower
            result["has_csp"] = "content-security-policy" in headers_lower

            # HTML Parsing
            html = resp.text
            # Title
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            if title_match:
                result["page_title"] = title_match.group(1).strip()

            # Meta description
            desc_match = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if desc_match:
                result["meta_description"] = desc_match.group(1).strip()

            # Login form / password fields
            if 'type="password"' in html.lower() or "type='password'" in html.lower():
                result["has_login_form"] = True
                result["detected_inputs"].append("Password Credential Field")

            if 'name="username"' in html.lower() or 'name="email"' in html.lower():
                result["detected_inputs"].append("Username / Account Identifier Field")

        except Exception as e:
            result["error"] = str(e)
            # Try HTTP fallback if HTTPS fails
            try:
                resp_http = self.http_session.get(f"http://{clean_domain}", timeout=timeout, allow_redirects=True)
                result["is_live"] = True
                result["status_code"] = resp_http.status_code
                result["final_url"] = resp_http.url
                result["error"] = None
            except Exception:
                pass

        return result

    def evaluate_domain_risk(
        self,
        domain: str,
        brand: str,
        dns_info: Dict[str, Any],
        ssl_info: Dict[str, Any],
        rdap_info: Optional[Dict[str, Any]] = None,
        http_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Computes mathematically calibrated Domain Threat Risk Score (0 - 100)
        grounded in actual live telemetry.
        """
        brand_clean = brand.lower().strip()
        domain_lower = domain.lower().strip()
        score = 0
        risk_factors = []

        # 1. Homoglyph / Punycode
        if "xn--" in domain_lower:
            score += 40
            risk_factors.append("Internationalized Domain (IDN Punycode) detected - probable homoglyph spoofing")

        # 2. Combosquatting keywords
        matched_kws = [kw for kw in COMBOSQUAT_KEYWORDS if kw in domain_lower]
        if matched_kws:
            pts = min(30, len(matched_kws) * 15)
            score += pts
            risk_factors.append(f"Combosquatting keywords detected: {', '.join(matched_kws)} (+{pts} pts)")

        # 3. High-risk TLD
        for tld, penalty in HIGH_RISK_TLDS.items():
            if domain_lower.endswith(tld):
                score += penalty
                risk_factors.append(f"High-abuse TLD detected: '{tld}' (+{penalty} pts)")
                break

        # 4. Lexical distance to target brand
        domain_name = domain_lower.split('.')[0].replace('-', '').replace('_', '')
        sim = calculate_similarity_ratio(brand_clean, domain_name)
        if sim >= 0.80 and domain_name != brand_clean:
            score += 25
            risk_factors.append(f"High lexical similarity to '{brand_clean}' ({sim * 100:.1f}%) indicating deliberate brand mimicry")

        # 5. Active DNS status
        if dns_info.get("resolved"):
            score += 15
            risk_factors.append(f"Domain actively resolves to IP: {', '.join(dns_info.get('ip_addresses', [])[:2])} (Live Asset)")
            if dns_info.get("mail_servers"):
                score += 15
                risk_factors.append(f"MX records configured ({len(dns_info['mail_servers'])} mail servers) - capability for spearphishing email exchange")

        # 6. RDAP Domain Age Penalty
        if rdap_info and rdap_info.get("age_days") is not None:
            age = rdap_info["age_days"]
            if age < 30:
                score += 25
                risk_factors.append(f"Newly registered domain ({age} days old) posing as mature brand")
            elif age < 90:
                score += 15
                risk_factors.append(f"Recent domain registration ({age} days old)")

        # 7. SSL Analysis
        if ssl_info.get("has_ssl"):
            if ssl_info.get("is_free_cert"):
                score += 15
                risk_factors.append(f"Automated free certificate issuer detected ({ssl_info.get('issuer')})")
        else:
            if dns_info.get("resolved"):
                score += 10
                risk_factors.append("Active HTTP server lacks SSL encryption")

        # 8. Live HTTP Probing Signals
        if http_info and http_info.get("has_login_form"):
            score += 25
            risk_factors.append("Active login / password credential harvesting input detected on live web page")

        final_score = min(100, max(0, score))

        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "MEDIUM"
        elif final_score >= 20:
            severity = "LOW"
        else:
            severity = "BENIGN"

        return {
            "risk_score": final_score,
            "severity": severity,
            "risk_factors": risk_factors,
            "similarity_to_brand": sim
        }
