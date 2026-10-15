# AegisOSINT System & Architecture Design

This directory contains the formal architectural, engineering, and user-experience design specifications for the **AegisOSINT** multi-vector brand impersonation and online fraud intelligence platform.

---

## 📑 Directory Index

| Document / Asset | Description | Target Audience |
| :--- | :--- | :--- |
| [**`SYSTEM_DESIGN_SPECIFICATION.md`**](file:///E:/osint-cia-2/Design/SYSTEM_DESIGN_SPECIFICATION.md) | High-Level Design (HLD) & Low-Level Design (LLD), component architecture, data flow diagrams (DFD), sequence diagrams, threat modeling (STRIDE), and NIST SP 800-86 cryptographic custody design. | Systems Architects, Security Engineers, Core Developers |
| [**`UI_UX_DESIGN_SYSTEM.md`**](file:///E:/osint-cia-2/Design/UI_UX_DESIGN_SYSTEM.md) | Dark-mode design system, typography scales, color token matrices, Cytoscape.js network visual taxonomy, HUD widget anatomy, and interaction state machines. | Frontend Engineers, UI/UX Designers, SOC Analysts |
| [**`SYSTEM_ARCHITECTURE_DIAGRAM.svg`**](file:///E:/osint-cia-2/Design/SYSTEM_ARCHITECTURE_DIAGRAM.svg) | High-resolution scalable vector graphic (SVG) depicting the 4-tier ingestion, forensics, risk scoring, and evidence custody topology. | All Stakeholders |

---

## 🏛️ High-Level Architectural Tiers

```
+-----------------------------------------------------------------------------------+
|                        TIER 1: MULTIMODAL INGESTION                               |
|  - DNS Prober (DoH/UDP)     - RDAP / WHOIS Prober       - SSL Certificate X.509   |
|  - Typosquat & Homoglyphs   - Social Account Harvester  - Phishing Lure Parser    |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                      TIER 2: SPECIALIZED FORENSIC ENGINES                         |
|  - Perceptual Hashing (pHash, dHash, wHash)    - Color Histogram Matching (CIELAB)|
|  - Combosquatting & Levenshtein Analysis       - Urgency & Sentiment NLP Lexicon  |
|  - RFC 7208 SPF / RFC 7489 DMARC Evaluator     - E.164 Phone Intelligence Prober  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|               TIER 3: GRAPH CORRELATION & CALIBRATED RISK SCORING                 |
|  - Heterogeneous Threat Knowledge Graph (Domain, IP, SSL, Brand, Actor, Lure)     |
|  - Degree / Betweenness / PageRank Centrality  - Multi-Vector Calibrated Formula  |
|  - Non-linear Adversarial Synergy Multipliers  - Explainable AI (XAI) Attribution |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|              TIER 4: NIST SP 800-86 EVIDENCE CUSTODY & AUTOMATED REMEDIATION      |
|  - SHA-256 + SHA3-512 Dual Digest Hashing      - Immutable Hash-Chained Ledger    |
|  - HMAC-SHA256 Digital Verification Seals      - ICANN RAA §3.18 Abuse Notices    |
|  - OASIS STIX 2.1 Threat Intel Bundles         - MISP 2.4 Event Synchronization   |
+-----------------------------------------------------------------------------------+
```
