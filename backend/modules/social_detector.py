"""
AegisOSINT - Social Media Brand Impersonation Detector
Detects fake social accounts, handle spoofing, bio mimicry, verification spoofing,
and scam-support redirection tactics across major social networks.
"""

import re
from typing import List, Dict, Any, Optional
from .domain_scanner import calculate_similarity_ratio, calculate_levenshtein


# Common impersonation prefixes and suffixes added by fraudsters
SOCIAL_AFFIXES = [
    "support", "official", "help", "care", "desk", "service", "team",
    "real", "security", "assist", "claims", "refunds", "updates", "bot"
]

# Scam indicators frequently present in fraudulent profile bios
SCAM_BIO_TRIGGERS = [
    ("dm for support", 25, "Solicits direct messages for customer support"),
    ("dm to recover", 30, "Account recovery lure"),
    ("whatsapp", 20, "Off-platform redirect to unmonitored WhatsApp chat"),
    ("wa.me", 25, "WhatsApp instant link redirect"),
    ("telegram", 20, "Off-platform Telegram handle redirect"),
    ("t.me/", 25, "Telegram channel/bot direct link"),
    ("airdrop", 30, "Cryptocurrency airdrop lure"),
    ("claim your", 25, "Prize / financial claim lure"),
    ("send seed phrase", 40, "Direct credential / seed phrase harvesting"),
    ("wallet validate", 35, "Cryptocurrency wallet drainer keyword"),
    ("bit.ly", 15, "Obfuscated URL shortener"),
    ("tinyurl", 15, "Obfuscated URL shortener"),
    ("linktr.ee", 15, "Third-party link aggregator"),
    ("24/7 official assistance", 20, "Generic high-pressure support claim"),
    ("authorized representative", 20, "False authority claim")
]

# Unicode checkmark emojis used by scammers to mimic platform verification badges
VERIFICATION_EMOJIS = ["✅", "✔", "☑", "✔️", "✓"]


class SocialMediaDetector:
    """Analyzes social media accounts and monitors handle impersonation campaigns."""

    def __init__(self):
        self.supported_platforms = ["Twitter/X", "Instagram", "Telegram", "LinkedIn", "YouTube", "TikTok", "Facebook"]

    def generate_suspect_handles(self, authentic_handle: str, max_variants: int = 20) -> List[Dict[str, Any]]:
        """Generates predictable impersonation handles used by threat actors."""
        base = authentic_handle.lower().strip().lstrip('@')
        variants = []
        seen = set()

        def add_variant(handle: str, pattern: str, explanation: str):
            if handle not in seen and handle != base:
                seen.add(handle)
                variants.append({
                    "handle": f"@{handle}",
                    "pattern": pattern,
                    "explanation": explanation,
                    "target_handle": f"@{base}"
                })

        # 1. Affix additions
        for affix in SOCIAL_AFFIXES:
            add_variant(f"{base}_{affix}", "Suffix Underscore", f"Added '_{affix}'")
            add_variant(f"{base}{affix}", "Suffix Concat", f"Appended '{affix}'")
            add_variant(f"{affix}_{base}", "Prefix Underscore", f"Prepended '{affix}_'")
            add_variant(f"{base}official", "Authority Claim", "Appended 'official'")
            add_variant(f"real_{base}", "Authority Claim", "Prepended 'real_'")

        # 2. Typos & Substitutions
        add_variant(f"{base}s", "Pluralization", "Appended 's'")
        if len(base) > 4:
            # Substitute 'o' with '0'
            if 'o' in base:
                add_variant(base.replace('o', '0'), "Leet Substitution", "Replaced 'o' with '0'")
            # Substitute 'l' with '1' or 'i'
            if 'l' in base:
                add_variant(base.replace('l', '1'), "Leet Substitution", "Replaced 'l' with '1'")

        return variants[:max_variants]

    def analyze_profile(self, profile_data: Dict[str, Any], authentic_brand: str, authentic_handle: str) -> Dict[str, Any]:
        """
        Deep forensic evaluation of a suspect social profile:
        - Handle distance and imitation ratio
        - Verification badge spoofing
        - Bio content intent & off-platform redirect analysis
        - Account age / follower ratio anomaly
        - Overall impersonation confidence score
        """
        suspect_handle = profile_data.get("handle", "").lower().strip().lstrip('@')
        display_name = profile_data.get("display_name", "")
        bio = profile_data.get("bio", "").lower()
        followers = profile_data.get("followers", 0)
        following = profile_data.get("following", 0)
        account_age_days = profile_data.get("account_age_days", 365)
        platform = profile_data.get("platform", "Twitter/X")
        is_officially_verified = profile_data.get("is_verified", False)

        clean_auth_handle = authentic_handle.lower().strip().lstrip('@')
        clean_brand = authentic_brand.lower().strip()

        score = 0
        indicators = []

        # 1. Handle similarity evaluation
        sim = calculate_similarity_ratio(clean_auth_handle, suspect_handle)
        lev = calculate_levenshtein(clean_auth_handle, suspect_handle)

        if suspect_handle == clean_auth_handle and not is_officially_verified:
            # Exact handle match on another platform or unverified duplicate
            score += 45
            indicators.append(f"Exact handle mimicry of authentic account (@{clean_auth_handle})")
        elif sim >= 0.75 or any(affix in suspect_handle for affix in SOCIAL_AFFIXES):
            score += 35
            indicators.append(f"Handle demonstrates high mimicry ({sim * 100:.1f}% lexical match to @{clean_auth_handle})")

        # 2. Display Name & Brand Mimicry
        if clean_brand in display_name.lower():
            score += 20
            indicators.append(f"Display name explicitly incorporates brand name '{authentic_brand}'")

        # 3. Emoji Verification Badge Spoofing
        has_fake_badge = any(emoji in display_name for emoji in VERIFICATION_EMOJIS)
        if has_fake_badge and not is_officially_verified:
            score += 30
            indicators.append("Deceptive visual verification badge emoji used in display name to trick victims")

        # 4. Bio Keyword & Lure Analysis
        bio_score = 0
        for trigger, pts, desc in SCAM_BIO_TRIGGERS:
            if trigger in bio:
                bio_score += pts
                indicators.append(f"Scam bio indicator: {desc} ('{trigger}')")
        score += min(40, bio_score)

        # 5. Account Age & Follower Ratio Anomaly
        if account_age_days < 60:
            score += 15
            indicators.append(f"Freshly created account ({account_age_days} days old) posing as mature brand")

        if followers < 250 and following > 1000:
            score += 15
            indicators.append(f"Suspicious follower-to-following ratio ({followers} followers vs {following} following)")
        elif followers < 50:
            score += 10
            indicators.append(f"Negligible follower count ({followers}) incompatible with genuine enterprise brand")

        # Final score calibration
        final_score = min(100, max(0, score))

        if final_score >= 80:
            verdict = "CONFIRMED_IMPERSONATION"
            severity = "CRITICAL"
        elif final_score >= 60:
            verdict = "HIGH_PROBABILITY_IMPERSONATOR"
            severity = "HIGH"
        elif final_score >= 40:
            verdict = "SUSPICIOUS_UNOFFICIAL_ACCOUNT"
            severity = "MEDIUM"
        else:
            verdict = "LIKELY_BENIGN_FAN_OR_UNAFFILIATED"
            severity = "LOW"

        return {
            "platform": platform,
            "suspect_handle": f"@{suspect_handle}",
            "display_name": display_name,
            "impersonation_score": final_score,
            "severity": severity,
            "verdict": verdict,
            "similarity_to_authentic": sim,
            "edit_distance": lev,
            "indicators": indicators,
            "is_officially_verified": is_officially_verified
        }
