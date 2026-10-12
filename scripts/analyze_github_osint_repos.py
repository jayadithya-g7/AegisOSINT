import json
import sys
from collections import defaultdict

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

with open("backend/data/github_osint_repos.json", "r", encoding="utf-8") as f:
    repos = json.load(f)

print(f"Total repos collected: {len(repos)}")

sorted_repos = sorted(repos.values(), key=lambda x: x["stars"], reverse=True)

categories = {
    "Domain & Phishing / Lookalikes": [],
    "Social & Username Impersonation": [],
    "Email OSINT & Verification": [],
    "Threat Intelligence & IOC Feeds": [],
    "Network / IP / DNS Infrastructure": [],
    "Metadata, Media & Content Forensics": [],
    "Frameworks & Investigation Platforms": []
}

keywords = {
    "Domain & Phishing / Lookalikes": ["domain", "phish", "typo", "squat", "url", "dns", "subdomain", "cert", "tld"],
    "Social & Username Impersonation": ["username", "social", "sherlock", "account", "profile", "twitter", "instagram", "telegram", "reddit", "impersonat"],
    "Email OSINT & Verification": ["email", "mail", "spf", "dmarc", "holehe", "ghunt", "mailbox", "breach", "pwned", "smtp"],
    "Threat Intelligence & IOC Feeds": ["threat", "intel", "ioc", "cve", "malware", "misp", "opencti", "alienvault", "yara", "sigma", "feed"],
    "Network / IP / DNS Infrastructure": ["ip", "port", "shodan", "asn", "network", "scan", "recon", "whois", "bgp"],
    "Metadata, Media & Content Forensics": ["image", "photo", "metadata", "exif", "logo", "hash", "visual", "media", "video"],
    "Frameworks & Investigation Platforms": ["framework", "platform", "toolkit", "spiderfoot", "maltego", "curated", "collection", "awesome"]
}

for r in sorted_repos:
    text = (r["name"] + " " + r["description"] + " " + " ".join(r["topics"])).lower()
    matched = False
    for cat, kws in keywords.items():
        if any(kw in text for kw in kws):
            categories[cat].append(r)
            matched = True
            break
    if not matched:
        categories["Frameworks & Investigation Platforms"].append(r)

print("\n" + "="*80)
print("REPOSITORIES CATEGORIZED FOR ONLINE FRAUD & BRAND IMPERSONATION:")
print("="*80)
for cat, r_list in categories.items():
    print(f"\n### {cat} ({len(r_list)} repos):")
    for r in r_list[:12]:
        d = (r['description'][:70] + "...") if r['description'] and len(r['description']) > 70 else (r['description'] or "")
        print(f"  - {r['name']:35s} | {r['stars']:5d} stars | {d}")
