# AegisOSINT: UI/UX Design System Specification

**Design Theme**: SOC Dark Ops & Cyber Threat Intelligence (CTI)  
**Standard**: Responsive, Accessible (WCAG 2.1 AA Compliant), Modern Monospace & Humanist Typography  
**Target Resolution**: 1920x1080 (Optimized for Multi-Monitor SOC Operation Centers and Laptops)  

---

## 1. Color System & Semantic Design Tokens

The interface adopts a high-contrast, low-fatigue dark theme specifically engineered for cybersecurity analysts working extended shifts in Security Operation Centers (SOC).

### 1.1 Base Surface Tokens
| Token Name | Hex Code | Semantic Role |
| :--- | :--- | :--- |
| `--bg-base` | `#080c14` | Deepest root canvas; maximizes contrast while reducing eye strain |
| `--bg-surface-1` | `#0f172a` | Primary card panels, navigation bar, sidebar surfaces |
| `--bg-surface-2` | `#1e293b` | Elevated cards, modal dialogs, input containers |
| `--bg-surface-elevated` | `#334155` | Hover states, active dropdown items, active tabs |
| `--border-subtle` | `#1e293b` | Non-intrusive container dividers |
| `--border-prominent`| `#334155` | Card borders, table headers, focused inputs |
| `--border-accent` | `#6366f1` | Active interactive selections, focused search fields |

### 1.2 Threat Severity Color Scale
| Severity Tier | Background Hex | Text / Border Hex | Semantic Meaning |
| :--- | :--- | :--- | :--- |
| `CRITICAL` (Score 80–100) | `rgba(239, 68, 68, 0.15)` | `#ef4444` (Red-500) | Weaponized phishing, exact logo clones, active credential harvester |
| `HIGH` (Score 60–79) | `rgba(249, 115, 22, 0.15)` | `#f97316` (Orange-500) | Registered lookalike domain, suspicious MX records, high handle mimicry |
| `MEDIUM` (Score 40–59) | `rgba(234, 179, 8, 0.15)` | `#eab308` (Yellow-500) | Parked combosquat domain, unverified social account, moderate urgency |
| `LOW` (Score 20–39) | `rgba(59, 130, 246, 0.15)` | `#3b82f6` (Blue-500) | Passive domain registration, benign similarity, legitimate vendor |
| `BENIGN` (Score 0–19) | `rgba(34, 197, 94, 0.15)` | `#22c55e` (Green-500) | Verified authentic brand asset, authoritative DNS/SSL configuration |

### 1.3 Interactive Accent Tokens
- **Brand Primary**: `#4f46e5` (Indigo-600) -> `#6366f1` (Indigo-500 hover)
- **Cyan Cyber Accent**: `#06b6d4` (Cyan-500) -> Used for telemetry streams, graph links, and probe timestamps
- **Success Glow**: `#10b981` (Emerald-500) -> Cryptographic hash match, verified evidence seal
- **Warning Amber**: `#f59e0b` (Amber-500) -> Missing DMARC policy, partial SPF coverage

---

## 2. Typography & Text Hierarchy

AegisOSINT uses a dual-typeface system pairing a modern sans-serif for UI chrome with a high-legibility monospace font for IP addresses, domain names, cryptographic hashes, and raw logs.

| Scale Role | Font Family | Size | Weight | Line Height | Usage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Display Heading** | Inter / System Sans | 24px | 700 (Bold) | 32px | Page titles, HUD headers |
| **Section Heading** | Inter / System Sans | 18px | 600 (SemiBold)| 26px | Panel headers, card titles |
| **Body Primary** | Inter / System Sans | 14px | 400 (Regular) | 20px | Descriptions, analysis text |
| **Body Secondary** | Inter / System Sans | 12px | 400 (Regular) | 16px | Metadata, tooltips, timestamps |
| **Code / Hash / IP** | JetBrains Mono / Consolas | 12px | 500 (Medium) | 18px | SHA-256 hashes, DNS records, IPs |

---

## 3. Cytoscape.js Network Graph Visual Taxonomy

The interactive threat graph visualizes interconnected infrastructure using color-coded nodes and relationship-defining edges.

### 3.1 Node Definitions
| Node Type | Color | Shape | Icon / Label |
| :--- | :--- | :--- | :--- |
| `Domain` | `#38bdf8` (Sky Blue) | Rectangle | `[D] domain.com` |
| `IP_Address` | `#a855f7` (Purple) | Ellipse | `[IP] 192.168.1.1` |
| `ASN` | `#f59e0b` (Amber) | Diamond | `AS13335 (Cloudflare)` |
| `Nameserver` | `#14b8a6` (Teal) | Hexagon | `[NS] ns1.nameserver.com` |
| `Threat_Actor` | `#ef4444` (Crimson) | Octagon | `[ACTOR] Syndicate Alpha` |
| `Brand_Target` | `#22c55e` (Emerald) | Round Rectangle | `[TARGET] PayPal` |
| `Lure_URL` | `#ec4899` (Pink) | Triangle | `[LURE] login-verify.html` |

### 3.2 Edge Definitions
- **`RESOLVES_TO`**: Directed solid line (`#94a3b8`), connecting `Domain` -> `IP_Address`.
- **`LOCATED_IN`**: Dashed line (`#f59e0b`), connecting `IP_Address` -> `ASN`.
- **`MANAGED_BY`**: Solid line (`#14b8a6`), connecting `Domain` -> `Nameserver`.
- **`TARGETS`**: Red neon line with animation (`#ef4444`), connecting `Threat_Actor` or `Domain` -> `Brand_Target`.
- **`EXFILTRATES_TO`**: High-contrast dotted line (`#ec4899`), connecting `Lure_URL` -> C2 webhook endpoint.

### 3.3 Graph Layout Modes
1. **CoSE (Compound Spring Embedder)**: Default physics-based organic cluster layout revealing natural campaign infrastructure clusters.
2. **Concentric**: Places the central brand target at center with threat rings radiating outward based on degree centrality.
3. **Breadthfirst**: Hierarchical top-down tree showing attack chain progression.

---

## 4. Workbench Component Anatomy

### 4.1 Triage HUD (Heads-Up Display)
- **Position**: Top horizontal bar.
- **Components**:
  - Live Threat Level Indicator (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `BENIGN`).
  - Metric Counters: Total Domains Scanned, Active Lookalikes, Sealed Evidence Blocks, Takedown Notices Ready.
  - Quick Search & Scan Launcher: Immediate input box accepting Domain, URL, or Brand Symbol.

### 4.2 Multi-Vector Investigation Panel
- **Split-View Architecture**:
  - **Left Column (40%)**: Target input parameters, quick brand pre-loaders (PayPal, Apple, Binance, Chase), and live prober output log console.
  - **Right Column (60%)**: Calibrated Risk Breakdown Gauge, Explainable AI (XAI) feature attribution bars, and multi-vector factor meters.

### 4.3 Evidence Vault & Chain of Custody Viewer
- **Modal Dialog**:
  - Displays the cryptographic block index, UTC timestamp, dual SHA-256 and SHA3-512 hashes.
  - One-click **"Verify Cryptographic Chain"** button: Evaluates every link in the ledger and renders an animated verification badge with zero-tamper confirmation.

### 4.4 Automated Takedown Studio
- **Tabbed Interface**:
  - **ICANN RAA §3.18 Abuse Notice**: Formatted legal notice with recipient registrar contact, evidence hashes, and dispute citations.
  - **Hosting Provider Cease & Desist**: Technical packet formatted for ISP abuse desks.
  - **STIX 2.1 Intelligence Bundle**: Syntax-highlighted JSON viewer with download button.
  - **MISP Event**: Standardized MISP attribute payload.
