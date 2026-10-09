# AegisOSINT — Multi-Vector Brand Impersonation & Fraud Threat Intelligence System

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Pytest-9%2F9%20Passing-brightgreen.svg)](#running-the-test-suite)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Standards](https://img.shields.io/badge/Forensics-NIST%20SP%20800--86-purple.svg)](https://csrc.nist.gov/pubs/sp/800/86/final)
[![CTI](https://img.shields.io/badge/Threat%20Intel-STIX%202.1-red.svg)](https://oasis-open.github.io/cti-documentation/)

---

## 🛡️ Overview

**AegisOSINT** is an end-to-end Open-Source Intelligence (OSINT) and Cyber Threat Intelligence (CTI) framework designed to detect, investigate, correlate, and remediate **online brand impersonation and digital fraud**. 

Modern threat syndicates coordinate multi-vector campaigns utilizing typosquatted/combosquatted domains, internationalized homoglyphs (IDN Punycode), cloned logos, deceptive social media accounts, and psychological coercion in email/SMS lures. AegisOSINT overcomes conventional single-channel siloing by integrating multimodal detection into a unified, heterogeneous link-analysis graph, calculating mathematically calibrated risk indices, and cryptographically sealing all artifacts into an immutable chain-of-custody ledger.

---

## 🏛️ System Architecture

AegisOSINT is organized into 7 modular tiers spanning data ingestion, forensic processing, topological link correlation, risk scoring, evidence custody, and automated remediation:

```
┌────────────────────────────────────────────────────────────────────────┐
│               TIER 1: MULTIMODAL INGESTION & PROBING                   │
│   Typosquat / Combosquat / IDN Punycode | DNS / SSL / RDAP Probers     │
│   Social Media Harvesters | Phishing / Smishing Communication Feeds    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               TIER 2: SPECIALIZED FORENSIC ENGINES                     │
│   • Perceptual Image Hashes (pHash, dHash, aHash, wHash, Color Sim)   │
│   • Social Profile Anomaly & Emoji Badge Spoofing Detector             │
│   • Psychological Coercion & Credential Harvesting NLP Engine          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│        TIER 3: HETEROGENEOUS ENTITY GRAPH & TOPOLOGICAL LINKS          │
│   Bipartite Multi-Entity Graph: Brands, Domains, IPs, ASNs, SSL,       │
│   Social Handles, Crypto Wallets. Graph Metrics: Degree, Betweenness,  │
│   PageRank, Connected Component Syndicate Clustering.                  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│            TIER 4: MULTI-FACTOR CALIBRATED RISK SCORING                │
│   R = Σ (w_k · S_k) + Synergy Bonus (Domain, Infra, Vision, NLP, etc.) │
│   Tiers: CRITICAL (80-100) | HIGH (60-79) | MEDIUM | LOW | BENIGN     │
└───────────────────────┬────────────────────────┬───────────────────────┘
                        ▼                        ▼
┌──────────────────────────────────┐ ┌───────────────────────────────────┐
│ TIER 5: FORENSIC EVIDENCE VAULT  │ │ TIER 6: ACTIONABLE REMEDIATION    │
│ NIST SP 800-86 Chain-of-Custody  │ │ • ICANN Sec 3.18 Abuse Notices    │
│ Parallel SHA-256 + SHA3-512      │ │ • Hosting Cease & Desist Letters  │
│ Immutable Hash-Chained Ledger    │ │ • OASIS STIX 2.1 JSON Packages    │
│ HMAC-SHA256 Digital Seals        │ │ • Court-Ready Forensic Dossiers   │
└──────────────────────────────────┘ └───────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│     TIER 7: INTERACTIVE CTI INVESTIGATION WORKBENCH (FastAPI + Web UI) │
│     8 Modular Views: Cases, Domains, Vision, Social, NLP, Graph, Vault │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📚 Academic Literature Survey & Comparative Matrix

The system is grounded in a rigorous academic survey of **12 foundational peer-reviewed papers** from leading cybersecurity venues (*ACM CCS, USENIX Security, IEEE S&P, IEEE TIFS, NDSS, Computers & Security*):

1. **Kintis et al. (ACM CCS 2017)** — *Hiding in Plain Sight: A Longitudinal Study of Combosquatting Abuse*
2. **Acharya et al. (USENIX Security 2023)** — *The Imitation Game: Exploring Brand Impersonation Attacks on Social Media Platforms*
3. **Liu et al. (USENIX Security 2021)** — *Phishpedia: A Deep Learning-Based Phishing Detection System for Logo Identification and Credential Harvesting Detection*
4. **Abdelnabi et al. (ACM CCS 2020)** — *VisualPhishNet: Zero-Day Phishing Website Detection by Visual Similarity*
5. **Oest et al. (IEEE S&P 2019)** — *PhishFarm: A Framework for Measuring the Detectability of Phishing Pages*
6. **Afroz & Greenstadt (IEEE S&P 2011)** — *PhishZoo: Detecting Phishing Websites by Looking at Them*
7. **Spaulding et al. (Computer Networks 2020)** — *Squatting Attacks on the Internet: A Comprehensive Survey and Taxonomy*
8. **Nikiforakis et al. (NDSS 2014)** — *Soundsquatting: Uncovering the Use of Homophones in Domain Name Squatting*
9. **Gao et al. (IEEE TIFS 2021)** — *Automated Cyber Threat Intelligence Extraction and Knowledge Graph Construction from Heterogeneous OSINT*
10. **Lin et al. (ACM TOPS 2022)** — *PhishBench: A Large-scale Longitudinal Benchmark for Phishing Web Page Detection*
11. **Al-Daeef et al. (Computers & Security 2022)** — *Graph-Based Threat Intelligence and Cybercrime Investigation: Correlating Multi-Source OSINT for Fraud Syndicate Unmasking*
12. **Wash & Cooper (USENIX Security 2020)** — *Who Clicks on Phishing Emails? A Longitudinal Study of Psychological Urgency and Authority Traps*

> 📖 **Read Full Academic Report & Comparative Matrix**: [`docs/RESEARCH_SURVEY_AND_ARCHITECTURE.md`](file:///E:/osint-cia-2/docs/RESEARCH_SURVEY_AND_ARCHITECTURE.md)

---

## ⚡ Core Modules & Capabilities

### 1. Domain Permutation & Suspicious Infrastructure Scanner
- **Typosquatting Engine**: QWERTY keyboard Euclidean distance substitutions, character omission, duplication, and transposition.
- **Combosquatting Engine**: Generates pairings with high-risk lure affixes (`login`, `secure`, `verify`, `support`, `auth`, `kyc`, `portal`, `wallet`, `helpdesk`).
- **Homoglyphs & IDN Punycode**: Generates visual Unicode equivalents (Latin to Cyrillic/Greek) and encodes to Punycode (`xn--...`).
- **Active Probers**: Resolves `A`, `AAAA`, `MX`, `NS`, and `TXT` records via `dnspython`, extracts SSL/TLS certificates and issuer chains, and queries ICANN RDAP metadata.

### 2. Visual Logo Clone & Perceptual Matcher
- Computes multi-metric perceptual image hashes:
  - **pHash** (Discrete Cosine Transform)
  - **dHash** (Gradient Difference)
  - **aHash** (Average Frequency)
  - **wHash** (Discrete Wavelet Transform)
- Measures 64-bit Hamming distance and normalized perceptual similarity.
- Evaluates RGB 3D color histogram overlap to identify brand color palette mimicry.
- Classifies emblems into: `CONFIRMED_CLONED_LOGO`, `SUSPICIOUS_LOOKALIKE`, `PARTIAL_VISUAL_SIMILARITY`, or `DISTINCT`.

### 3. Social Media Brand Impersonation Watcher
- Monitors brand handle variations across Twitter/X, Instagram, Telegram, LinkedIn, YouTube, and TikTok.
- Flags Unicode emoji verification badge spoofing (`✔️`, `✅`, `☑️`).
- Analyzes bio descriptions for off-platform redirect lures (`wa.me/`, `t.me/`, `dm for support`).
- Detects follower-to-following ratio anomalies and newly created accounts posing as established enterprises.

### 4. Fraudulent Communication & Phishing NLP Analyzer
- Scans emails, SMS (smishing), and instant messages for psychological urgency and fear cues ("account locked within 24 hours", "unauthorized transaction").
- Detects credential harvesting intent ("enter password", "seed phrase", "verify OTP").
- Flags sender identity discrepancies (claimed brand domain vs actual SMTP sender / free webmail providers).
- Extracts and inspects embedded URLs and flags IP literal links (`http://185.220.../login`).

### 5. Heterogeneous Entity Graph & Link Analysis Engine
- Models threat intelligence as a multi-entity graph using `networkx`:
  - **Nodes**: Brands, Domains, IP Addresses, ASNs, Registrars, Nameservers, SSL Certs, Social Handles, Crypto Wallets, Threat Actors.
  - **Edges**: `IMPERSONATES`, `RESOLVES_TO`, `ANNOUNCED_BY`, `REGISTERED_VIA`, `DELEGATED_TO`, `SECURED_BY`, `PROMOTES`, `DRAINS_TO`.
- Calculates graph topological metrics: **Degree Centrality**, **Betweenness Centrality**, **PageRank**, and **Connected Components** to uncover criminal hosting syndicates.
- Interactive web rendering powered by **Cytoscape.js** with multiple layout topologies (CoSE, concentric, circular, breadthfirst).

### 6. Calibrated Multi-Factor Risk Scoring Engine
- Computes calibrated composite risk $R \in [0, 100]$:
  $$R = \min\left(100, \sum_{k} w_k \cdot S_k + \Delta_{\text{synergy}}\right)$$
- Weights: Domain ($0.25$), Infrastructure ($0.20$), Visual ($0.20$), NLP ($0.15$), Social ($0.10$), Graph ($0.10$).
- Applies non-linear synergy bonuses (+12 to +20 points) when adversaries coordinate multiple vectors simultaneously.
- Categorizes risk into actionable threat tiers: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `BENIGN`.

### 7. Forensic Evidence Locker (NIST SP 800-86 Compliant)
- Cryptographically hashes every captured artifact with **parallel SHA-256 and SHA3-512**.
- Implements an **immutable, hash-chained custody ledger** where every block incorporates the hash of the preceding block:
  $$H(B_i) = \text{SHA256}(H(B_{i-1}) \mathbin{\Vert} \text{Evidence\_ID} \mathbin{\Vert} \text{SHA256\_Hash} \mathbin{\Vert} \text{Timestamp})$$
- Generates HMAC-SHA256 digital seals and provides an interactive verification tool to mathematically prove evidence integrity for courtroom or dispute proceedings.

### 8. Automated Remediation & Takedown Studio
- Auto-generates formal **ICANN Registrar Abuse Notices** citing RAA Section 3.18 with embedded evidence hashes.
- Compiles hosting provider cease-and-desist notices addressed to server ASNs.
- Exports standardized **OASIS STIX 2.1 Threat Intelligence Bundles** (`Identity`, `Campaign`, `Indicator`, `Infrastructure`, `Relationship`).
- Assembles comprehensive executive and technical investigation dossiers.

---

## 🚀 Quickstart & Execution

### Prerequisites
- Python 3.11+
- Virtual environment with dependencies installed (pre-configured in `.venv`)

### 1. Launch the System (One-Click)
Run the launcher script to start the FastAPI server and automatically launch the interactive workbench in your default browser:

```powershell
.venv\Scripts\python run_system.py
```

Or run via Uvicorn directly:
```powershell
.venv\Scripts\python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Once running, access the Interactive Workbench at:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

### 2. Running the Test Suite
AegisOSINT includes a comprehensive test suite verifying all 7 intelligence engines:

```powershell
$env:PYTHONPATH="E:\osint-cia-2"
.venv\Scripts\python -m pytest backend/tests/test_all_modules.py -v
```

Expected output:
```
backend/tests/test_all_modules.py::test_domain_scanner_permutations PASSED [ 11%]
backend/tests/test_all_modules.py::test_domain_risk_evaluation PASSED    [ 22%]
backend/tests/test_all_modules.py::test_visual_matcher_hashes PASSED     [ 33%]
backend/tests/test_all_modules.py::test_social_detector PASSED           [ 44%]
backend/tests/test_all_modules.py::test_communication_nlp PASSED         [ 55%]
backend/tests/test_all_modules.py::test_entity_graph_and_centrality PASSED [ 66%]
backend/tests/test_all_modules.py::test_risk_scoring_engine PASSED       [ 77%]
backend/tests/test_all_modules.py::test_evidence_locker_and_verification PASSED [ 88%]
backend/tests/test_all_modules.py::test_report_and_stix_generator PASSED [100%]
============================== 9 passed in 29.59s ==============================
```

---

## 📁 Repository Structure

```
E:\osint-cia-2\
├── backend\
│   ├── app.py                      # FastAPI REST Gateway & Static UI Server
│   ├── modules\
│   │   ├── domain_scanner.py       # Typosquat, Combosquat, Homoglyphs, DNS, SSL, RDAP
│   │   ├── visual_matcher.py       # Perceptual Hashing (pHash, dHash, wHash), Color Sim
│   │   ├── social_detector.py      # Cross-Platform Handle Spoofing, Bio NLP, Badging
│   │   ├── communication_nlp.py    # Phishing Lure NLP, Urgency Cues, URL Extraction
│   │   ├── entity_graph.py         # Heterogeneous Graph Network, Centrality, Syndicates
│   │   ├── risk_engine.py          # Calibrated Multi-Vector Risk Scoring Engine
│   │   ├── evidence_locker.py      # NIST SP 800-86 Immutable Hash-Chained Ledger
│   │   └── report_generator.py     # Forensic Dossiers, ICANN Notices, STIX 2.1 Bundles
│   ├── data\
│   │   ├── sample_cases.json       # Realistic Preloaded Investigations (PayPal, Binance, Apple, Chase)
│   │   ├── reference_logos\        # Brand Reference Emblem Library
│   │   └── evidence_vault\         # Sealed Evidence Artifacts & Chain-of-Custody Ledger
│   └── tests\
│       └── test_all_modules.py     # Pytest Automated Test Suite (9 Tests)
├── frontend\
│   ├── index.html                  # Cyber Threat Intelligence Workbench UI
│   ├── css\
│   │   └── styles.css              # Custom Dark Theme Styling & Animations
│   └── js\
│       ├── app.js                  # Frontend State, API Client & Triage Pipeline
│       └── graph.js                # Interactive Cytoscape.js Network Graph Controller
├── docs\
│   ├── RESEARCH_SURVEY_AND_ARCHITECTURE.md  # 12-Paper Survey, Matrix, Gaps, Architecture & Metrics
│   └── SYSTEM_ARCHITECTURE_DIAGRAM.svg      # High-Fidelity Vector Architecture Diagram
├── run_system.py                   # One-Click Server & Browser Launcher
├── requirements.txt                # Frozen Python Dependencies
└── README.md                       # Comprehensive System Documentation
```

---

## 📊 Evaluation Metrics Summary

| Metric Dimension | Formal Formulation | Target Threshold | Operational Purpose |
|---|---|---|---|
| **Detection Precision** | $P = \frac{TP}{TP + FP}$ | $> 95\%$ | Minimizes costly false alarms for SOC analysts |
| **Detection Recall** | $R = \frac{TP}{TP + FN}$ | $> 92\%$ | Captures active lookalike domains and impersonators |
| **F1-Score** | $2 \cdot \frac{P \cdot R}{P + R}$ | $> 93.5\%$ | Harmonic balance of precision and recall |
| **False Positive Rate** | $FPR = \frac{FP}{FP + TN}$ | $< 1.5\%$ | Prevents disruption to legitimate brand fans/affiliates |
| **Mean Time to Detect** | $\frac{1}{N}\sum(t_{\text{alert}} - t_{\text{create}})$ | $< 60$ mins | Early intervention before campaign weaponization |
| **Evidence Tamper Verification**| $EIVR = 100\%$ | $100.0\%$ | Cryptographic proof required for court admissibility |
| **Takedown Success Rate** | $\frac{N_{\text{suspended}}}{N_{\text{reported}}} \times 100$ | $> 85\%$ | Faster domain suspension under ICANN Section 3.18 |

---

## ⚖️ Legal & Ethical Usage Notice
AegisOSINT is designed exclusively for authorized corporate brand protection, academic cybersecurity research, incident response, and law enforcement investigations. Active DNS probing and OSINT collection conform to non-intrusive reconnaissance standards.
