"""
AegisOSINT - Fraudulent Communication & Phishing Lure NLP Analyzer
Detects social engineering tactics, urgency cues, credential-harvesting triggers,
sender-brand discrepancies, and malicious embedded hyperlinks.
"""

import re
from typing import List, Dict, Any, Optional
import urllib.parse


# Psychological pressure & urgency cue lexicons
URGENCY_TRIGGERS = [
    (r"\b(immediately|urgent|right away|promptly)\b", 15, "Explicit high-urgency language"),
    (r"\b(within \d+ (hours?|minutes?|days?)|24 hours?|48 hours?)\b", 25, "Arbitrary deadline coercion"),
    (r"\b(suspended|terminated|deactivated|disabled|restricted|frozen|locked)\b", 25, "Punitive threat / account loss coercion"),
    (r"\b(unauthorized (access|transaction|activity)|suspicious activity)\b", 20, "Manufactured security alert / panic inducement"),
    (r"\b(action required|important notice|security alert|final notice)\b", 15, "False administrative imperative"),
    (r"\b(avoid (suspension|closure|fee|legal action))\b", 20, "Threat of negative consequence")
]

# Credential & financial harvesting lexicons
HARVESTING_TRIGGERS = [
    (r"\b(enter your (password|pin|otp|credentials|passcode))\b", 35, "Direct credential solicitation"),
    (r"\b(seed phrase|secret recovery phrase|private key)\b", 40, "Cryptographic wallet key theft"),
    (r"\b(verify your (account|identity|identity|profile|billing|card))\b", 25, "Identity / KYC spoofing verification lure"),
    (r"\b(update your (payment|credit card|billing|banking))\b", 30, "Financial data harvesting"),
    (r"\b(click (here|the link below|to verify|to unlock|to login))\b", 20, "High-pressure call-to-action click lure"),
    (r"\b(claim (your reward|refund|bonus|prize|airdrop))\b", 25, "Unsolicited financial reward / refund bait"),
    (r"\b(tax refund|wire transfer|overdue payment|invoice attached)\b", 20, "Financial invoice / refund pretext")
]


class CommunicationNLPAnalyzer:
    """Analyzes emails, SMS, and direct messages for social engineering indicators."""

    def __init__(self):
        self.url_regex = re.compile(
            r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?',
            re.IGNORECASE
        )
        self.email_regex = re.compile(
            r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            re.IGNORECASE
        )

    def extract_urls(self, text: str) -> List[str]:
        """Extracts all embedded HTTP/HTTPS URLs from communication text."""
        return self.url_regex.findall(text)

    def extract_emails(self, text: str) -> List[str]:
        """Extracts all email addresses present in text."""
        return self.email_regex.findall(text)

    def analyze_communication(
        self,
        text: str,
        sender: Optional[str] = None,
        claimed_brand: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Deep behavioral NLP inspection of communication payload:
        - Psychological urgency and fear triggers
        - Financial / Credential harvesting intent
        - Sender header vs claimed brand domain discrepancy
        - Suspicious URL extraction and destination domain correlation
        """
        text_lower = text.lower()
        score = 0
        urgency_score = 0
        harvest_score = 0
        detected_cues = []
        extracted_urls = self.extract_urls(text)
        extracted_emails = self.extract_emails(text)

        # 1. Evaluate urgency & fear coercion cues
        for pattern, pts, desc in URGENCY_TRIGGERS:
            matches = re.findall(pattern, text_lower)
            if matches:
                urgency_score += pts
                detected_cues.append({
                    "category": "Urgency & Psychological Coercion",
                    "description": desc,
                    "points": pts,
                    "matched": [m[0] if isinstance(m, tuple) else m for m in matches]
                })

        # 2. Evaluate credential & financial harvesting intent
        for pattern, pts, desc in HARVESTING_TRIGGERS:
            matches = re.findall(pattern, text_lower)
            if matches:
                harvest_score += pts
                detected_cues.append({
                    "category": "Credential & Financial Harvesting",
                    "description": desc,
                    "points": pts,
                    "matched": [m[0] if isinstance(m, tuple) else m for m in matches]
                })

        score += min(45, urgency_score)
        score += min(45, harvest_score)

        # 3. Sender domain spoofing / discrepancy check
        sender_discrepancy = False
        if sender and claimed_brand:
            brand_clean = claimed_brand.lower().strip()
            sender_lower = sender.lower().strip()
            # If sender domain does not contain brand or is a free webmail service
            free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "proton.me", "mail.com"]
            if any(p in sender_lower for p in free_providers):
                score += 30
                sender_discrepancy = True
                detected_cues.append({
                    "category": "Sender Identity Anomaly",
                    "description": f"Official brand communication sent from free public webmail provider ({sender})",
                    "points": 30,
                    "matched": [sender]
                })
            elif brand_clean not in sender_lower:
                score += 25
                sender_discrepancy = True
                detected_cues.append({
                    "category": "Sender Identity Anomaly",
                    "description": f"Sender address '{sender}' does not originate from authoritative brand domain '{brand_clean}.com'",
                    "points": 25,
                    "matched": [sender]
                })

        # 4. Embedded URL Analysis
        url_threat_cues = []
        for url in extracted_urls:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""
            if claimed_brand and claimed_brand.lower() not in hostname.lower():
                score += 20
                url_threat_cues.append({
                    "url": url,
                    "domain": hostname,
                    "flag": f"Destination hostname '{hostname}' does not match claimed brand identity"
                })
            # Check for IP literal hostnames (e.g. http://185.220.101.5/login)
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
                score += 30
                url_threat_cues.append({
                    "url": url,
                    "domain": hostname,
                    "flag": "Direct IP literal URL bypasses DNS domain reputation checks"
                })

        final_score = min(100, max(0, score))

        if final_score >= 80:
            severity = "CRITICAL"
            verdict = "CONFIRMED_FRAUDULENT_COMMUNICATION"
        elif final_score >= 60:
            severity = "HIGH"
            verdict = "PROBABLE_PHISHING_ATTEMPT"
        elif final_score >= 40:
            severity = "MEDIUM"
            verdict = "SUSPICIOUS_COMMUNICATION"
        elif final_score >= 20:
            severity = "LOW"
            verdict = "LOW_RISK_COMMUNICATION"
        else:
            severity = "BENIGN"
            verdict = "LEGITIMATE_COMMUNICATION"

        return {
            "fraud_score": final_score,
            "severity": severity,
            "verdict": verdict,
            "subscores": {
                "urgency_coercion": min(45, urgency_score),
                "harvesting_intent": min(45, harvest_score),
                "sender_discrepancy": 30 if sender_discrepancy else 0,
                "url_threat": len(url_threat_cues) * 20
            },
            "detected_cues": detected_cues,
            "extracted_urls": extracted_urls,
            "url_threat_cues": url_threat_cues,
            "extracted_emails": extracted_emails,
            "word_count": len(text.split())
        }
