"""
AegisOSINT Complete Design Diagrams Generator
Generates 8 high-fidelity standalone SVGs and 8 native Draw.io XML files (.drawio)
in Design/design/ for:
1. UML Use Case Diagram
2. UML Class Diagram
3. UML Sequence Diagram
4. UML Activity / Action Diagram
5. UML State Machine / State Space Diagram
6. Cross-Functional Swimlane Diagram
7. Entity-Relationship Diagram (ERD)
8. Graph-Based Link Analysis & Network Topology Diagram
"""

import os
import html
from pathlib import Path

OUT_DIR = Path(r"E:\osint-cia-2\Design\design")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Helper for Draw.io XML wrapper
def wrap_drawio(diagram_id, name, cells_xml, width=1800, height=1200):
    return f"""<mxfile host="app.diagrams.net" modified="2026-10-15T00:00:00.000Z" agent="AegisOSINT" version="21.0.0" type="device">
  <diagram id="{diagram_id}" name="{html.escape(name)}">
    <mxGraphModel dx="1422" dy="794" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="{width}" pageHeight="{height}" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>
{cells_xml}
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>"""

print("Preparing Diagram 1: UML Use Case Diagram...")
# -------------------------------------------------------------
# 1. USE CASE DIAGRAM
# -------------------------------------------------------------
svg_1 = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 1100" width="100%" height="100%" style="background:#090d16; font-family:'Segoe UI', Inter, -apple-system, sans-serif;">
  <defs>
    <linearGradient id="bgHeader" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#4f46e5"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
    <linearGradient id="actorGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1e293b"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>
    <filter id="shadow" x="-10%" y="-10%" width="120%" height="120%">
      <feDropShadow dx="0" dy="6" stdDeviation="8" flood-color="#000000" flood-opacity="0.6"/>
    </filter>
    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#94a3b8"/>
    </marker>
    <marker id="includeArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#06b6d4"/>
    </marker>
    <marker id="extendArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#f59e0b"/>
    </marker>
  </defs>

  <!-- Title Banner -->
  <rect x="40" y="30" width="1520" height="70" rx="10" fill="url(#bgHeader)" filter="url(#shadow)"/>
  <text x="800" y="65" text-anchor="middle" fill="#ffffff" font-size="22" font-weight="bold" letter-spacing="1">UML USE CASE DIAGRAM: MULTI-VECTOR OSINT BRAND IMPERSONATION &amp; FRAUD DETECTION SYSTEM</text>
  <text x="800" y="88" text-anchor="middle" fill="#e0e7ff" font-size="13">Specification of System Boundaries, Primary/Secondary Actors, Functional Use Cases, and &lt;&lt;include&gt;&gt; / &lt;&lt;extend&gt;&gt; Relationships</text>

  <!-- System Boundary Container -->
  <rect x="360" y="130" width="880" height="920" rx="16" fill="#0f172a" stroke="#334155" stroke-width="2" filter="url(#shadow)"/>
  <rect x="360" y="130" width="880" height="40" rx="16" fill="#1e293b"/>
  <text x="800" y="156" text-anchor="middle" fill="#38bdf8" font-size="14" font-weight="bold" letter-spacing="1.5">SYSTEM BOUNDARY: AEGIS-OSINT THREAT DETECTION &amp; INVESTIGATION SUITE</text>

  <!-- ACTORS (Left: Primary Human & Daemon Actors) -->
  <!-- Actor 1: Brand Protection / SOC Analyst -->
  <g transform="translate(60, 260)">
    <circle cx="110" cy="40" r="24" fill="#1e293b" stroke="#38bdf8" stroke-width="2.5"/>
    <line x1="110" y1="64" x2="110" y2="120" stroke="#38bdf8" stroke-width="2.5"/>
    <line x1="75" y1="85" x2="145" y2="85" stroke="#38bdf8" stroke-width="2.5"/>
    <line x1="110" y1="120" x2="80" y2="165" stroke="#38bdf8" stroke-width="2.5"/>
    <line x1="110" y1="120" x2="140" y2="165" stroke="#38bdf8" stroke-width="2.5"/>
    <rect x="15" y="175" width="190" height="45" rx="6" fill="#0f172a" stroke="#38bdf8" stroke-width="1.5"/>
    <text x="110" y="195" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Brand Protection Lead /</text>
    <text x="110" y="210" text-anchor="middle" fill="#94a3b8" font-size="11">SOC Analyst</text>
  </g>

  <!-- Actor 2: CTI Forensic Investigator -->
  <g transform="translate(60, 520)">
    <circle cx="110" cy="40" r="24" fill="#1e293b" stroke="#818cf8" stroke-width="2.5"/>
    <line x1="110" y1="64" x2="110" y2="120" stroke="#818cf8" stroke-width="2.5"/>
    <line x1="75" y1="85" x2="145" y2="85" stroke="#818cf8" stroke-width="2.5"/>
    <line x1="110" y1="120" x2="80" y2="165" stroke="#818cf8" stroke-width="2.5"/>
    <line x1="110" y1="120" x2="140" y2="165" stroke="#818cf8" stroke-width="2.5"/>
    <rect x="15" y="175" width="190" height="45" rx="6" fill="#0f172a" stroke="#818cf8" stroke-width="1.5"/>
    <text x="110" y="195" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">CTI Forensic Investigator</text>
    <text x="110" y="210" text-anchor="middle" fill="#94a3b8" font-size="11">(Digital Evidence Custodian)</text>
  </g>

  <!-- Actor 3: Automated OSINT Daemon -->
  <g transform="translate(60, 780)">
    <rect x="70" y="20" width="80" height="70" rx="8" fill="#1e293b" stroke="#a855f7" stroke-width="2.5"/>
    <circle cx="95" cy="50" r="6" fill="#a855f7"/>
    <circle cx="125" cy="50" r="6" fill="#a855f7"/>
    <path d="M 90 70 Q 110 82 130 70" stroke="#a855f7" stroke-width="2.5" fill="none"/>
    <line x1="110" y1="20" x2="110" y2="5" stroke="#a855f7" stroke-width="2.5"/>
    <circle cx="110" cy="4" r="3" fill="#a855f7"/>
    <rect x="15" y="105" width="190" height="45" rx="6" fill="#0f172a" stroke="#a855f7" stroke-width="1.5"/>
    <text x="110" y="125" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Automated Recon Daemon</text>
    <text x="110" y="140" text-anchor="middle" fill="#94a3b8" font-size="11">(Timer / CT Log Crawler)</text>
  </g>

  <!-- ACTORS (Right: Secondary Responding & Sharing Entities) -->
  <!-- Actor 4: Domain Registrar / Hosting Abuse Desk -->
  <g transform="translate(1330, 360)">
    <circle cx="110" cy="40" r="24" fill="#1e293b" stroke="#f43f5e" stroke-width="2.5"/>
    <line x1="110" y1="64" x2="110" y2="120" stroke="#f43f5e" stroke-width="2.5"/>
    <line x1="75" y1="85" x2="145" y2="85" stroke="#f43f5e" stroke-width="2.5"/>
    <line x1="110" y1="120" x2="80" y2="165" stroke="#f43f5e" stroke-width="2.5"/>
    <line x1="110" y1="120" x2="140" y2="165" stroke="#f43f5e" stroke-width="2.5"/>
    <rect x="15" y="175" width="190" height="45" rx="6" fill="#0f172a" stroke="#f43f5e" stroke-width="1.5"/>
    <text x="110" y="195" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Registrar Abuse Desk /</text>
    <text x="110" y="210" text-anchor="middle" fill="#94a3b8" font-size="11">Hosting Provider (ASN)</text>
  </g>

  <!-- Actor 5: Global Threat Sharing Feeds (STIX / MISP) -->
  <g transform="translate(1330, 680)">
    <rect x="70" y="20" width="80" height="70" rx="8" fill="#1e293b" stroke="#10b981" stroke-width="2.5"/>
    <line x1="85" y1="40" x2="135" y2="40" stroke="#10b981" stroke-width="2"/>
    <line x1="85" y1="55" x2="135" y2="55" stroke="#10b981" stroke-width="2"/>
    <line x1="85" y1="70" x2="115" y2="70" stroke="#10b981" stroke-width="2"/>
    <rect x="15" y="105" width="190" height="45" rx="6" fill="#0f172a" stroke="#10b981" stroke-width="1.5"/>
    <text x="110" y="125" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Global CTI Feeds</text>
    <text x="110" y="140" text-anchor="middle" fill="#94a3b8" font-size="11">(STIX 2.1 / MISP 2.4)</text>
  </g>

  <!-- USE CASES (Inside System Boundary) -->
  <!-- UC-1: Brand Watchlist -->
  <g id="uc1">
    <ellipse cx="530" cy="220" rx="130" ry="32" fill="#1e293b" stroke="#38bdf8" stroke-width="2"/>
    <text x="530" y="218" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-1: Define Brand Watchlist &amp;</text>
    <text x="530" y="232" text-anchor="middle" fill="#94a3b8" font-size="10">Reference Emblems</text>
  </g>

  <!-- UC-2: Permutation Generation -->
  <g id="uc2">
    <ellipse cx="530" cy="330" rx="130" ry="32" fill="#1e293b" stroke="#818cf8" stroke-width="2"/>
    <text x="530" y="328" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-2: Proactive Permutation Gen</text>
    <text x="530" y="342" text-anchor="middle" fill="#94a3b8" font-size="10">(Typos, Combos, Homoglyphs)</text>
  </g>

  <!-- UC-3: Active Network Probing -->
  <g id="uc3">
    <ellipse cx="800" cy="330" rx="125" ry="32" fill="#1e293b" stroke="#06b6d4" stroke-width="2"/>
    <text x="800" y="328" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-3: Execute Active Probing</text>
    <text x="800" y="342" text-anchor="middle" fill="#94a3b8" font-size="10">(DoH DNS, RDAP, TLS X.509)</text>
  </g>

  <!-- UC-4: Web DOM & Form Action Inspection -->
  <g id="uc4">
    <ellipse cx="530" cy="460" rx="130" ry="32" fill="#1e293b" stroke="#06b6d4" stroke-width="2"/>
    <text x="530" y="458" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-4: Inspect Web Interfaces</text>
    <text x="530" y="472" text-anchor="middle" fill="#94a3b8" font-size="10">&amp; Anti-Cloaking Form Actions</text>
  </g>

  <!-- UC-5: Visual Logo Perceptual Hashing -->
  <g id="uc5">
    <ellipse cx="800" cy="460" rx="125" ry="32" fill="#1e293b" stroke="#06b6d4" stroke-width="2"/>
    <text x="800" y="458" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-5: Logo Visual Similarity</text>
    <text x="800" y="472" text-anchor="middle" fill="#94a3b8" font-size="10">(64-bit pHash, dHash, CIELAB)</text>
  </g>

  <!-- UC-6: Social Media Monitor -->
  <g id="uc6">
    <ellipse cx="1070" cy="460" rx="125" ry="32" fill="#1e293b" stroke="#06b6d4" stroke-width="2"/>
    <text x="1070" y="458" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-6: Social Account Recon</text>
    <text x="1070" y="472" text-anchor="middle" fill="#94a3b8" font-size="10">&amp; Emoji Badge Spoofing</text>
  </g>

  <!-- UC-7: Email Forensics (SPF/DMARC) -->
  <g id="uc7">
    <ellipse cx="530" cy="590" rx="130" ry="32" fill="#1e293b" stroke="#06b6d4" stroke-width="2"/>
    <text x="530" y="588" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-7: Email Security Auditing</text>
    <text x="530" y="602" text-anchor="middle" fill="#94a3b8" font-size="10">(RFC 7208 SPF / RFC 7489 DMARC)</text>
  </g>

  <!-- UC-8: Threat Knowledge Graph -->
  <g id="uc8">
    <ellipse cx="800" cy="590" rx="130" ry="32" fill="#1e293b" stroke="#a855f7" stroke-width="2"/>
    <text x="800" y="588" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-8: Threat Graph Correlation</text>
    <text x="800" y="602" text-anchor="middle" fill="#94a3b8" font-size="10">&amp; Centrality Link Analysis</text>
  </g>

  <!-- UC-9: Calibrated Risk Engine -->
  <g id="uc9">
    <ellipse cx="800" cy="710" rx="130" ry="32" fill="#1e293b" stroke="#f59e0b" stroke-width="2.5"/>
    <text x="800" y="708" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-9: Calibrated Risk Scoring</text>
    <text x="800" y="722" text-anchor="middle" fill="#f59e0b" font-size="10">&amp; Synergy Bonus Evaluation</text>
  </g>

  <!-- UC-10: Evidence Ledger (NIST SP 800-86) -->
  <g id="uc10">
    <ellipse cx="800" cy="830" rx="130" ry="32" fill="#1e293b" stroke="#10b981" stroke-width="2"/>
    <text x="800" y="828" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-10: Seal Evidence in Ledger</text>
    <text x="800" y="842" text-anchor="middle" fill="#10b981" font-size="10">(SHA-256 + SHA3 Hash Chain)</text>
  </g>

  <!-- UC-11: Takedown Notices (ICANN) -->
  <g id="uc11">
    <ellipse cx="1070" cy="710" rx="125" ry="32" fill="#1e293b" stroke="#f43f5e" stroke-width="2"/>
    <text x="1070" y="708" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-11: Generate Takedown Dossier</text>
    <text x="1070" y="722" text-anchor="middle" fill="#94a3b8" font-size="10">(ICANN RAA §3.18 Abuse Notice)</text>
  </g>

  <!-- UC-12: STIX 2.1 / MISP Threat Intel Export -->
  <g id="uc12">
    <ellipse cx="1070" cy="830" rx="125" ry="32" fill="#1e293b" stroke="#10b981" stroke-width="2"/>
    <text x="1070" y="828" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">UC-12: Export Threat Intel</text>
    <text x="1070" y="842" text-anchor="middle" fill="#94a3b8" font-size="10">(STIX 2.1 Bundles &amp; MISP Events)</text>
  </g>

  <!-- ACTOR ASSOCIATION LINES -->
  <!-- Analyst connects to UC-1, UC-2, UC-8, UC-9, UC-11 -->
  <line x1="260" y1="350" x2="405" y2="230" stroke="#475569" stroke-width="1.8"/>
  <line x1="260" y1="350" x2="405" y2="330" stroke="#475569" stroke-width="1.8"/>
  <line x1="260" y1="350" x2="675" y2="590" stroke="#475569" stroke-width="1.8"/>
  <line x1="260" y1="350" x2="675" y2="710" stroke="#475569" stroke-width="1.8"/>

  <!-- Investigator connects to UC-8, UC-10, UC-11, UC-12 -->
  <line x1="260" y1="610" x2="670" y2="590" stroke="#475569" stroke-width="1.8"/>
  <line x1="260" y1="610" x2="670" y2="830" stroke="#475569" stroke-width="1.8"/>
  <line x1="260" y1="610" x2="945" y2="710" stroke="#475569" stroke-width="1.8"/>

  <!-- Recon Daemon connects to UC-2, UC-3, UC-4, UC-6 -->
  <line x1="260" y1="870" x2="405" y2="345" stroke="#475569" stroke-width="1.8" stroke-dasharray="4,4"/>
  <line x1="260" y1="870" x2="680" y2="340" stroke="#475569" stroke-width="1.8" stroke-dasharray="4,4"/>
  <line x1="260" y1="870" x2="420" y2="475" stroke="#475569" stroke-width="1.8" stroke-dasharray="4,4"/>

  <!-- Secondary Actor lines -->
  <line x1="1195" y1="710" x2="1330" y2="460" stroke="#f43f5e" stroke-width="2"/>
  <line x1="1195" y1="830" x2="1330" y2="780" stroke="#10b981" stroke-width="2"/>

  <!-- INCLUDE & EXTEND RELATIONSHIPS -->
  <!-- UC-2 includes UC-3 -->
  <path d="M 660 330 L 675 330" stroke="#06b6d4" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#includeArrow)"/>
  <text x="668" y="322" text-anchor="middle" fill="#06b6d4" font-size="10" font-weight="bold">&lt;&lt;include&gt;&gt;</text>

  <!-- Probes include UC-8 (Threat Graph) -->
  <path d="M 800 362 L 800 428" stroke="#06b6d4" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#includeArrow)"/>
  <text x="835" y="398" fill="#06b6d4" font-size="10" font-weight="bold">&lt;&lt;include&gt;&gt;</text>

  <path d="M 800 492 L 800 558" stroke="#06b6d4" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#includeArrow)"/>
  <text x="835" y="528" fill="#06b6d4" font-size="10" font-weight="bold">&lt;&lt;include&gt;&gt;</text>

  <!-- UC-8 includes UC-9 (Risk Engine) -->
  <path d="M 800 622 L 800 678" stroke="#06b6d4" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#includeArrow)"/>
  <text x="835" y="652" fill="#06b6d4" font-size="10" font-weight="bold">&lt;&lt;include&gt;&gt;</text>

  <!-- UC-9 includes UC-10 (Evidence Custody) -->
  <path d="M 800 742 L 800 798" stroke="#06b6d4" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#includeArrow)"/>
  <text x="835" y="772" fill="#06b6d4" font-size="10" font-weight="bold">&lt;&lt;include&gt;&gt;</text>

  <!-- UC-9 extends UC-11 (Takedown Notice) condition: Risk >= 80 -->
  <path d="M 945 710 L 930 710" stroke="#f59e0b" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#extendArrow)"/>
  <text x="935" y="698" text-anchor="middle" fill="#f59e0b" font-size="10" font-weight="bold">&lt;&lt;extend&gt;&gt;</text>
  <text x="935" y="728" text-anchor="middle" fill="#94a3b8" font-size="9">[Risk &gt;= 80]</text>

  <!-- UC-10 includes UC-12 (STIX / MISP Export) -->
  <path d="M 930 830 L 945 830" stroke="#06b6d4" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#includeArrow)"/>
  <text x="938" y="822" text-anchor="middle" fill="#06b6d4" font-size="10" font-weight="bold">&lt;&lt;include&gt;&gt;</text>

  <!-- Legend Box -->
  <rect x="380" y="940" width="840" height="85" rx="8" fill="#1e293b" stroke="#334155"/>
  <text x="400" y="962" fill="#e2e8f0" font-size="11" font-weight="bold">DIAGRAM NOTATION &amp; RELATIONSHIP LEGEND:</text>
  <line x1="400" y1="985" x2="450" y2="985" stroke="#475569" stroke-width="2"/>
  <text x="460" y="989" fill="#94a3b8" font-size="10">Actor-Use Case Association</text>
  <line x1="620" y1="985" x2="670" y2="985" stroke="#06b6d4" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#includeArrow)"/>
  <text x="680" y="989" fill="#06b6d4" font-size="10">&lt;&lt;include&gt;&gt; Mandatory Ingestion/Processing Flow</text>
  <line x1="950" y1="985" x2="1000" y2="985" stroke="#f59e0b" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#extendArrow)"/>
  <text x="1010" y="989" fill="#f59e0b" font-size="10">&lt;&lt;extend&gt;&gt; Conditional High-Risk Escalation</text>
  <circle cx="410" cy="1010" r="5" fill="#38bdf8"/>
  <text x="425" y="1014" fill="#94a3b8" font-size="10">Primary Human Actor</text>
  <rect x="620" y="1005" width="12" height="10" fill="#a855f7" rx="2"/>
  <text x="640" y="1014" fill="#94a3b8" font-size="10">Automated Timer Daemon</text>
  <circle cx="955" cy="1010" r="5" fill="#f43f5e"/>
  <text x="970" y="1014" fill="#94a3b8" font-size="10">External Abuse Desk / Threat Sharing System</text>
</svg>"""

with open(OUT_DIR / "01_USE_CASE_DIAGRAM.svg", "w", encoding="utf-8") as f:
    f.write(svg_1)

# Draw.io XML for Diagram 1
xml_1 = """
        <mxCell id="2" value="Brand Protection Lead /&#xa;SOC Analyst" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;outlineConnect=0;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="120" y="280" width="50" height="90" as="geometry"/>
        </mxCell>
        <mxCell id="3" value="CTI Forensic Investigator&#xa;(Evidence Custodian)" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;outlineConnect=0;fillColor=#1e293b;strokeColor=#818cf8;fontColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="120" y="520" width="50" height="90" as="geometry"/>
        </mxCell>
        <mxCell id="4" value="Automated Recon Daemon&#xa;(Timer / CT Crawler)" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;outlineConnect=0;fillColor=#1e293b;strokeColor=#a855f7;fontColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="120" y="780" width="50" height="90" as="geometry"/>
        </mxCell>
        <mxCell id="5" value="Registrar Abuse Desk /&#xa;Hosting Provider (ASN)" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;outlineConnect=0;fillColor=#1e293b;strokeColor=#f43f5e;fontColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="1420" y="420" width="50" height="90" as="geometry"/>
        </mxCell>
        <mxCell id="6" value="Global CTI Feeds&#xa;(STIX 2.1 / MISP 2.4)" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;outlineConnect=0;fillColor=#1e293b;strokeColor=#10b981;fontColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="1420" y="740" width="50" height="90" as="geometry"/>
        </mxCell>
        <mxCell id="7" value="AegisOSINT Threat Detection &amp; Investigation Suite" style="shape=folder;fontStyle=1;spacingTop=10;tabWidth=200;tabHeight=30;tabPosition=left;html=1;fillColor=#0f172a;strokeColor=#334155;fontColor=#38bdf8;" vertex="1" parent="1">
          <mxGeometry x="320" y="140" width="980" height="880" as="geometry"/>
        </mxCell>
        <mxCell id="10" value="UC-1: Define Brand Watchlist &amp; Emblems" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="400" y="210" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="11" value="UC-2: Proactive Permutation Generation&#xa;(Typos, Combos, IDN Homoglyphs)" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#818cf8;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="400" y="320" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="12" value="UC-3: Execute Active Probing&#xa;(DoH DNS, RDAP, TLS X.509)" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#06b6d4;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="720" y="320" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="13" value="UC-4: Inspect Web Interfaces&#xa;&amp; Anti-Cloaking Form Actions" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#06b6d4;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="400" y="450" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="14" value="UC-5: Logo Visual Similarity&#xa;(64-bit pHash, dHash, CIELAB)" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#06b6d4;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="720" y="450" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="15" value="UC-6: Social Account Recon&#xa;&amp; Emoji Badge Spoofing" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#06b6d4;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="1020" y="450" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="16" value="UC-7: Email Security Auditing&#xa;(RFC 7208 SPF / RFC 7489 DMARC)" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#06b6d4;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="400" y="580" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="17" value="UC-8: Threat Graph Correlation&#xa;&amp; Centrality Link Analysis" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#a855f7;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="720" y="580" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="18" value="UC-9: Calibrated Risk Scoring&#xa;&amp; Synergy Bonus Evaluation" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#f59e0b;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="720" y="700" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="19" value="UC-10: Seal Evidence in Ledger&#xa;(SHA-256 + SHA3 Hash Chain)" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#10b981;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="720" y="820" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="20" value="UC-11: Generate Takedown Dossier&#xa;(ICANN RAA §3.18 Abuse Notice)" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#f43f5e;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="1020" y="700" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="21" value="UC-12: Export Threat Intel&#xa;(STIX 2.1 Bundles &amp; MISP Events)" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#10b981;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="1020" y="820" width="240" height="60" as="geometry"/>
        </mxCell>
        <mxCell id="30" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#475569;" edge="1" parent="1" source="2" target="10"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="31" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#475569;" edge="1" parent="1" source="2" target="11"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="32" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#475569;" edge="1" parent="1" source="2" target="17"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="33" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#475569;" edge="1" parent="1" source="3" target="17"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="34" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#475569;" edge="1" parent="1" source="3" target="19"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="35" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#475569;" edge="1" parent="1" source="4" target="12"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="36" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#f43f5e;strokeWidth=2;" edge="1" parent="1" source="20" target="5"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="37" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#10b981;strokeWidth=2;" edge="1" parent="1" source="21" target="6"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="40" value="&amp;lt;&amp;lt;include&amp;gt;&amp;gt;" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#06b6d4;dashed=1;fontColor=#06b6d4;" edge="1" parent="1" source="11" target="12"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="41" value="&amp;lt;&amp;lt;include&amp;gt;&amp;gt;" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#06b6d4;dashed=1;fontColor=#06b6d4;" edge="1" parent="1" source="12" target="17"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="42" value="&amp;lt;&amp;lt;include&amp;gt;&amp;gt;" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#06b6d4;dashed=1;fontColor=#06b6d4;" edge="1" parent="1" source="17" target="18"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="43" value="&amp;lt;&amp;lt;include&amp;gt;&amp;gt;" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#06b6d4;dashed=1;fontColor=#06b6d4;" edge="1" parent="1" source="18" target="19"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="44" value="&amp;lt;&amp;lt;extend&amp;gt;&amp;gt;&#xa;[Risk &gt;= 80]" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#f59e0b;dashed=1;fontColor=#f59e0b;" edge="1" parent="1" source="18" target="20"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="45" value="&amp;lt;&amp;lt;include&amp;gt;&amp;gt;" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#06b6d4;dashed=1;fontColor=#06b6d4;" edge="1" parent="1" source="19" target="21"><mxGeometry relative="1" as="geometry"/></mxCell>
"""
with open(OUT_DIR / "01_USE_CASE_DIAGRAM.drawio", "w", encoding="utf-8") as f:
    f.write(wrap_drawio("diag_usecase", "UML Use Case Diagram", xml_1, 1600, 1100))

print("Diagram 1 completed.")

print("Preparing Diagram 2: UML Class Diagram...")
# -------------------------------------------------------------
# 2. CLASS DIAGRAM
# -------------------------------------------------------------
svg_2 = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1700 1200" width="100%" height="100%" style="background:#090d16; font-family:'Segoe UI', Inter, -apple-system, sans-serif;">
  <defs>
    <linearGradient id="bgHeader2" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#4f46e5"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
    <filter id="shadow2" x="-5%" y="-5%" width="110%" height="110%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.5"/>
    </filter>
    <marker id="assocArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#94a3b8"/>
    </marker>
    <marker id="compDiamond" viewBox="0 0 12 12" refX="1" refY="6" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M 1 6 L 6 1 L 11 6 L 6 11 z" fill="#38bdf8" stroke="#38bdf8"/>
    </marker>
    <marker id="aggDiamond" viewBox="0 0 12 12" refX="1" refY="6" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M 1 6 L 6 1 L 11 6 L 6 11 z" fill="#0f172a" stroke="#818cf8" stroke-width="1.5"/>
    </marker>
  </defs>

  <!-- Title Banner -->
  <rect x="40" y="30" width="1620" height="70" rx="10" fill="url(#bgHeader2)" filter="url(#shadow2)"/>
  <text x="850" y="65" text-anchor="middle" fill="#ffffff" font-size="22" font-weight="bold" letter-spacing="1">UML CLASS DIAGRAM: OBJECT-ORIENTED DOMAIN &amp; FORENSIC ARCHITECTURE</text>
  <text x="850" y="88" text-anchor="middle" fill="#e0e7ff" font-size="13">Detailed Class Specifications, Member Visibility (+ / - / #), Method Signatures, Composition, and Dependency Hierarchies</text>

  <!-- Package 1: Ingestion & Recon (Top-Left) -->
  <rect x="50" y="130" width="480" height="490" rx="12" fill="#0f172a" stroke="#334155" stroke-width="1.5"/>
  <rect x="50" y="130" width="220" height="30" rx="6" fill="#1e293b"/>
  <text x="65" y="150" fill="#38bdf8" font-size="12" font-weight="bold">PACKAGE: ingestion</text>

  <!-- Class: BrandProfile -->
  <g transform="translate(70, 180)">
    <rect x="0" y="0" width="440" height="150" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" filter="url(#shadow2)"/>
    <rect x="0" y="0" width="440" height="30" rx="6" fill="#082f49"/>
    <text x="220" y="20" text-anchor="middle" fill="#38bdf8" font-size="12" font-weight="bold">&lt;&lt;entity&gt;&gt; BrandProfile</text>
    <text x="15" y="50" fill="#cbd5e1" font-size="11">+ brand_id: UUID</text>
    <text x="15" y="66" fill="#cbd5e1" font-size="11">+ brand_name: str</text>
    <text x="15" y="82" fill="#cbd5e1" font-size="11">+ official_domains: List[str]</text>
    <text x="15" y="98" fill="#cbd5e1" font-size="11">+ reference_logo_hashes: List[str]</text>
    <line x1="0" y1="106" x2="440" y2="106" stroke="#334155"/>
    <text x="15" y="124" fill="#38bdf8" font-size="11">+ register_domain(domain: str): bool</text>
    <text x="15" y="140" fill="#38bdf8" font-size="11">+ add_reference_logo(img_bytes: bytes): str</text>
  </g>

  <!-- Class: DomainProber -->
  <g transform="translate(70, 360)">
    <rect x="0" y="0" width="440" height="230" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" filter="url(#shadow2)"/>
    <rect x="0" y="0" width="440" height="30" rx="6" fill="#082f49"/>
    <text x="220" y="20" text-anchor="middle" fill="#38bdf8" font-size="12" font-weight="bold">DomainProber</text>
    <text x="15" y="50" fill="#cbd5e1" font-size="11">- doh_resolvers: List[str]</text>
    <text x="15" y="66" fill="#cbd5e1" font-size="11">- request_timeout: float = 8.0</text>
    <text x="15" y="82" fill="#cbd5e1" font-size="11">- idna_codec: str = "punycode"</text>
    <line x1="0" y1="90" x2="440" y2="90" stroke="#334155"/>
    <text x="15" y="108" fill="#38bdf8" font-size="11">+ clean_domain_string(raw: str): str</text>
    <text x="15" y="124" fill="#38bdf8" font-size="11">+ generate_permutations(domain: str): List[str]</text>
    <text x="15" y="140" fill="#38bdf8" font-size="11">+ resolve_doh_dns(domain: str): Dict[str, List[str]]</text>
    <text x="15" y="156" fill="#38bdf8" font-size="11">+ query_rdap_whois(domain: str): Dict[str, Any]</text>
    <text x="15" y="172" fill="#38bdf8" font-size="11">+ extract_ssl_x509(host: str, port: int): Dict[str, Any]</text>
    <text x="15" y="188" fill="#38bdf8" font-size="11">+ probe_ct_logs(domain: str): List[str]</text>
    <text x="15" y="204" fill="#38bdf8" font-size="11">+ check_drop_catch_status(domain: str): bool</text>
    <text x="15" y="220" fill="#38bdf8" font-size="11">+ evaluate_domain_risk(perm: str, base: str): float</text>
  </g>

  <!-- Package 2: Multi-Modal Forensics (Top-Center) -->
  <rect x="560" y="130" width="560" height="490" rx="12" fill="#0f172a" stroke="#334155" stroke-width="1.5"/>
  <rect x="560" y="130" width="220" height="30" rx="6" fill="#1e293b"/>
  <text x="575" y="150" fill="#818cf8" font-size="12" font-weight="bold">PACKAGE: forensics</text>

  <!-- Class: VisualSimilarity -->
  <g transform="translate(580, 180)">
    <rect x="0" y="0" width="520" height="150" rx="6" fill="#1e293b" stroke="#818cf8" stroke-width="1.5" filter="url(#shadow2)"/>
    <rect x="0" y="0" width="520" height="30" rx="6" fill="#1e1b4b"/>
    <text x="260" y="20" text-anchor="middle" fill="#818cf8" font-size="12" font-weight="bold">VisualSimilarityEngine</text>
    <text x="15" y="50" fill="#cbd5e1" font-size="11">- hash_size: int = 8 (64-bit)</text>
    <text x="15" y="66" fill="#cbd5e1" font-size="11">- color_bins: int = 64</text>
    <line x1="0" y1="74" x2="520" y2="74" stroke="#334155"/>
    <text x="15" y="92" fill="#818cf8" font-size="11">+ compute_phash_64(img: Image): str</text>
    <text x="15" y="108" fill="#818cf8" font-size="11">+ compute_dhash(img: Image): str</text>
    <text x="15" y="124" fill="#818cf8" font-size="11">+ hamming_distance(h1: str, h2: str): int</text>
    <text x="15" y="140" fill="#818cf8" font-size="11">+ match_cielab_histograms(img1: Image, img2: Image): float</text>
  </g>

  <!-- Class: ContentInspector & EmailAuditor -->
  <g transform="translate(580, 360)">
    <rect x="0" y="0" width="520" height="230" rx="6" fill="#1e293b" stroke="#818cf8" stroke-width="1.5" filter="url(#shadow2)"/>
    <rect x="0" y="0" width="520" height="30" rx="6" fill="#1e1b4b"/>
    <text x="260" y="20" text-anchor="middle" fill="#818cf8" font-size="12" font-weight="bold">ContentAndProtocolAuditor</text>
    <text x="15" y="50" fill="#cbd5e1" font-size="11">- urgency_lexicon: Set[str]</text>
    <text x="15" y="66" fill="#cbd5e1" font-size="11">- credential_regex: List[Pattern]</text>
    <text x="15" y="82" fill="#cbd5e1" font-size="11">- form_action_blacklist: Set[str]</text>
    <line x1="0" y1="90" x2="520" y2="90" stroke="#334155"/>
    <text x="15" y="108" fill="#818cf8" font-size="11">+ strip_zero_width_spaces(text: str): str</text>
    <text x="15" y="124" fill="#818cf8" font-size="11">+ extract_urgency_score(body: str): float</text>
    <text x="15" y="140" fill="#818cf8" font-size="11">+ audit_form_actions_c2(html_dom: str): Dict[str, Any]</text>
    <text x="15" y="156" fill="#818cf8" font-size="11">+ parse_rfc7208_spf(txt_records: List[str]): Dict[str, Any]</text>
    <text x="15" y="172" fill="#818cf8" font-size="11">+ parse_rfc7489_dmarc(dmarc_record: str): Dict[str, Any]</text>
    <text x="15" y="188" fill="#818cf8" font-size="11">+ audit_bimi_vmc(bimi_record: str): bool</text>
    <text x="15" y="204" fill="#818cf8" font-size="11">+ normalize_e164_phone(phone_raw: str): str</text>
    <text x="15" y="220" fill="#818cf8" font-size="11">+ calculate_social_impersonation(profile: Dict): float</text>
  </g>

  <!-- Package 3: Threat Knowledge Graph (Top-Right) -->
  <rect x="1150" y="130" width="500" height="490" rx="12" fill="#0f172a" stroke="#334155" stroke-width="1.5"/>
  <rect x="1150" y="130" width="220" height="30" rx="6" fill="#1e293b"/>
  <text x="1165" y="150" fill="#a855f7" font-size="12" font-weight="bold">PACKAGE: correlation</text>

  <!-- Class: ThreatGraph -->
  <g transform="translate(1170, 180)">
    <rect x="0" y="0" width="460" height="220" rx="6" fill="#1e293b" stroke="#a855f7" stroke-width="1.5" filter="url(#shadow2)"/>
    <rect x="0" y="0" width="460" height="30" rx="6" fill="#3b0764"/>
    <text x="230" y="20" text-anchor="middle" fill="#a855f7" font-size="12" font-weight="bold">HeterogeneousThreatGraph</text>
    <text x="15" y="50" fill="#cbd5e1" font-size="11">- nodes: Dict[str, EntityNode]</text>
    <text x="15" y="66" fill="#cbd5e1" font-size="11">- edges: List[RelationEdge]</text>
    <text x="15" y="82" fill="#cbd5e1" font-size="11">- graph_engine: NetworkX.Graph</text>
    <line x1="0" y1="90" x2="460" y2="90" stroke="#334155"/>
    <text x="15" y="108" fill="#a855f7" font-size="11">+ insert_entity(id: str, type: str, props: Dict): EntityNode</text>
    <text x="15" y="124" fill="#a855f7" font-size="11">+ insert_relation(src: str, dst: str, rel: str, w: float): bool</text>
    <text x="15" y="140" fill="#a855f7" font-size="11">+ compute_degree_centrality(): Dict[str, float]</text>
    <text x="15" y="156" fill="#a855f7" font-size="11">+ compute_betweenness_centrality(): Dict[str, float]</text>
    <text x="15" y="172" fill="#a855f7" font-size="11">+ compute_pagerank(alpha: float = 0.85): Dict[str, float]</text>
    <text x="15" y="188" fill="#a855f7" font-size="11">+ isolate_syndicate_clusters(): List[Set[str]]</text>
    <text x="15" y="204" fill="#a855f7" font-size="11">+ export_cytoscape_json(): Dict[str, Any]</text>
  </g>

  <!-- Class: EntityNode & RelationEdge -->
  <g transform="translate(1170, 430)">
    <rect x="0" y="0" width="220" height="160" rx="6" fill="#1e293b" stroke="#a855f7" stroke-width="1.5" filter="url(#shadow2)"/>
    <rect x="0" y="0" width="220" height="28" rx="6" fill="#3b0764"/>
    <text x="110" y="19" text-anchor="middle" fill="#a855f7" font-size="11" font-weight="bold">EntityNode</text>
    <text x="12" y="46" fill="#cbd5e1" font-size="10">+ node_id: str</text>
    <text x="12" y="62" fill="#cbd5e1" font-size="10">+ entity_type: str</text>
    <text x="12" y="78" fill="#cbd5e1" font-size="10">+ label: str</text>
    <text x="12" y="94" fill="#cbd5e1" font-size="10">+ risk_score: float</text>
    <text x="12" y="110" fill="#cbd5e1" font-size="10">+ properties: Dict</text>
    <line x1="0" y1="118" x2="220" y2="118" stroke="#334155"/>
    <text x="12" y="136" fill="#a855f7" font-size="10">+ get_degree(): int</text>
    <text x="12" y="150" fill="#a855f7" font-size="10">+ to_dict(): Dict</text>

    <rect x="240" y="0" width="220" height="160" rx="6" fill="#1e293b" stroke="#a855f7" stroke-width="1.5" filter="url(#shadow2)"/>
    <rect x="240" y="0" width="220" height="28" rx="6" fill="#3b0764"/>
    <text x="350" y="19" text-anchor="middle" fill="#a855f7" font-size="11" font-weight="bold">RelationEdge</text>
    <text x="252" y="46" fill="#cbd5e1" font-size="10">+ source_id: str</text>
    <text x="252" y="62" fill="#cbd5e1" font-size="10">+ target_id: str</text>
    <text x="252" y="78" fill="#cbd5e1" font-size="10">+ relation_type: str</text>
    <text x="252" y="94" fill="#cbd5e1" font-size="10">+ weight: float</text>
    <text x="252" y="110" fill="#cbd5e1" font-size="10">+ discovered_at: str</text>
    <line x1="240" y1="118" x2="460" y2="118" stroke="#334155"/>
    <text x="252" y="136" fill="#a855f7" font-size="10">+ is_directed(): bool</text>
    <text x="252" y="150" fill="#a855f7" font-size="10">+ to_dict(): Dict</text>
  </g>

  <!-- Package 4: Risk Scoring & Custody (Bottom) -->
  <rect x="50" y="650" width="1600" height="490" rx="12" fill="#0f172a" stroke="#334155" stroke-width="1.5"/>
  <rect x="50" y="650" width="260" height="30" rx="6" fill="#1e293b"/>
  <text x="65" y="670" fill="#f59e0b" font-size="12" font-weight="bold">PACKAGE: risk_scoring_and_custody</text>

  <!-- Class: CalibratedRiskEngine -->
  <g transform="translate(70, 700)">
    <rect x="0" y="0" width="480" height="230" rx="6" fill="#1e293b" stroke="#f59e0b" stroke-width="1.5" filter="url(#shadow2)"/>
    <rect x="0" y="0" width="480" height="30" rx="6" fill="#451a03"/>
    <text x="240" y="20" text-anchor="middle" fill="#f59e0b" font-size="12" font-weight="bold">CalibratedRiskEngine</text>
    <text x="15" y="50" fill="#cbd5e1" font-size="11">- weights: Dict[str, float] = {w_domain: 0.25, ...}</text>
    <text x="15" y="66" fill="#cbd5e1" font-size="11">- synergy_thresholds: Dict[str, float]</text>
    <text x="15" y="82" fill="#cbd5e1" font-size="11">- max_clamped_score: float = 100.0</text>
    <line x1="0" y1="90" x2="480" y2="90" stroke="#334155"/>
    <text x="15" y="108" fill="#f59e0b" font-size="11">+ calculate_composite_risk(vector_scores: Dict): float</text>
    <text x="15" y="124" fill="#f59e0b" font-size="11">+ evaluate_adversarial_synergy(scores: Dict): float</text>
    <text x="15" y="140" fill="#f59e0b" font-size="11">+ derive_threat_tier(score: float): ThreatTier</text>
    <text x="15" y="156" fill="#f59e0b" font-size="11">+ generate_xai_attribution(scores: Dict): Dict[str, float]</text>
    <text x="15" y="172" fill="#f59e0b" font-size="11">+ recommend_action(tier: ThreatTier): RemediationAction</text>
  </g>

  <!-- Class: EvidenceLocker & EvidenceBlock (NIST SP 800-86) -->
  <g transform="translate(580, 700)">
    <rect x="0" y="0" width="520" height="230" rx="6" fill="#1e293b" stroke="#10b981" stroke-width="1.5" filter="url(#shadow2)"/>
    <rect x="0" y="0" width="520" height="30" rx="6" fill="#064e3b"/>
    <text x="260" y="20" text-anchor="middle" fill="#10b981" font-size="12" font-weight="bold">NISTEvidenceLocker (SP 800-86)</text>
    <text x="15" y="50" fill="#cbd5e1" font-size="11">- ledger_file: Path = "chain_of_custody_ledger.json"</text>
    <text x="15" y="66" fill="#cbd5e1" font-size="11">- vault_dir: Path = "evidence_vault/"</text>
    <text x="15" y="82" fill="#cbd5e1" font-size="11">- hmac_secret_key: bytes</text>
    <line x1="0" y1="90" x2="520" y2="90" stroke="#334155"/>
    <text x="15" y="108" fill="#10b981" font-size="11">+ seal_evidence_artifact(raw_data: bytes, uri: str, type: str): EvidenceBlock</text>
    <text x="15" y="124" fill="#10b981" font-size="11">+ compute_dual_hashes(data: bytes): Tuple[str, str]</text>
    <text x="15" y="140" fill="#10b981" font-size="11">+ append_to_hash_chain(block: EvidenceBlock): bool</text>
    <text x="15" y="156" fill="#10b981" font-size="11">+ verify_chain_integrity(): Tuple[bool, int, str]</text>
    <text x="15" y="172" fill="#10b981" font-size="11">+ generate_hmac_digital_seal(block: EvidenceBlock): str</text>
    <text x="15" y="188" fill="#10b981" font-size="11">+ export_evidence_receipt(evidence_id: UUID): Dict[str, Any]</text>
  </g>

  <!-- Class: TakedownStudio -->
  <g transform="translate(1130, 700)">
    <rect x="0" y="0" width="500" height="230" rx="6" fill="#1e293b" stroke="#f43f5e" stroke-width="1.5" filter="url(#shadow2)"/>
    <rect x="0" y="0" width="500" height="30" rx="6" fill="#4c0519"/>
    <text x="250" y="20" text-anchor="middle" fill="#f43f5e" font-size="12" font-weight="bold">RemediationAndTakedownStudio</text>
    <text x="15" y="50" fill="#cbd5e1" font-size="11">- icann_raa_template: str = "ICANN RAA §3.18"</text>
    <text x="15" y="66" fill="#cbd5e1" font-size="11">- stix_version: str = "2.1"</text>
    <text x="15" y="82" fill="#cbd5e1" font-size="11">- misp_distribution: int = 3</text>
    <line x1="0" y1="90" x2="500" y2="90" stroke="#334155"/>
    <text x="15" y="108" fill="#f43f5e" font-size="11">+ generate_icann_abuse_notice(incident: Dict): str</text>
    <text x="15" y="124" fill="#f43f5e" font-size="11">+ generate_hosting_cease_and_desist(asn_info: Dict): str</text>
    <text x="15" y="140" fill="#f43f5e" font-size="11">+ compile_stix21_bundle(incident: Dict): Dict[str, Any]</text>
    <text x="15" y="156" fill="#f43f5e" font-size="11">+ export_misp_event_json(incident: Dict): Dict[str, Any]</text>
    <text x="15" y="172" fill="#f43f5e" font-size="11">+ assemble_forensic_dossier(incident_id: str): Path</text>
  </g>

  <!-- Class Diagram Legend -->
  <rect x="70" y="970" width="1560" height="130" rx="8" fill="#1e293b" stroke="#334155"/>
  <text x="95" y="995" fill="#e2e8f0" font-size="12" font-weight="bold">UML CLASS NOTATION &amp; RELATIONSHIP KEY:</text>
  <path d="M 95 1030 L 140 1030" stroke="#38bdf8" stroke-width="2" marker-start="url(#compDiamond)"/>
  <text x="150" y="1034" fill="#cbd5e1" font-size="11">Composition (Strong ownership, lifetime dependency)</text>
  <path d="M 600 1030 L 645 1030" stroke="#818cf8" stroke-width="2" marker-start="url(#aggDiamond)"/>
  <text x="655" y="1034" fill="#cbd5e1" font-size="11">Aggregation (Shared reference, independent lifetime)</text>
  <path d="M 1150 1030 L 1195 1030" stroke="#94a3b8" stroke-width="2" stroke-dasharray="5,4" marker-end="url(#assocArrow)"/>
  <text x="1205" y="1034" fill="#cbd5e1" font-size="11">Dependency / Method Invocation (&lt;&lt;uses&gt;&gt;)</text>
  <text x="95" y="1075" fill="#38bdf8" font-size="11">+ Public Member</text>
  <text x="250" y="1075" fill="#f59e0b" font-size="11">- Private Member</text>
  <text x="400" y="1075" fill="#10b981" font-size="11"># Protected Member</text>
  <text x="600" y="1075" fill="#94a3b8" font-size="11">Class Methods: name(param: Type): ReturnType</text>
  <text x="1050" y="1075" fill="#cbd5e1" font-size="11">NIST SP 800-86 Cryptographic Invariant: H(B_i) = SHA256(H(B_i-1) || Data)</text>
</svg>"""

with open(OUT_DIR / "02_CLASS_DIAGRAM.svg", "w", encoding="utf-8") as f:
    f.write(svg_2)

xml_2 = """
        <mxCell id="100" value="BrandProfile" style="swimlane;fontStyle=1;align=center;verticalAlign=top;childLayout=stackLayout;horizontal=1;startSize=26;horizontalStack=0;resizeParent=1;resizeParentMax=0;resizeLast=0;collapsible=1;marginBottom=0;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#38bdf8;" vertex="1" parent="1">
          <mxGeometry x="80" y="160" width="360" height="160" as="geometry"/>
        </mxCell>
        <mxCell id="101" value="+ brand_id: UUID&#xa;+ brand_name: str&#xa;+ official_domains: List[str]&#xa;+ reference_logo_hashes: List[str]" style="text;strokeColor=none;fillColor=none;align=left;verticalAlign=top;spacingLeft=4;spacingRight=4;overflow=hidden;rotatable=0;points=[[0,0.5],[1,0.5]];portConstraint=eastwest;fontColor=#cbd5e1;" vertex="1" parent="100">
          <mxGeometry y="26" width="360" height="64" as="geometry"/>
        </mxCell>
        <mxCell id="102" value="" style="line;strokeWidth=1;fillColor=none;align=left;verticalAlign=middle;spacingTop=-1;spacingLeft=3;spacingRight=3;rotatable=0;labelPosition=right;points=[];portConstraint=eastwest;strokeColor=#334155;" vertex="1" parent="100">
          <mxGeometry y="90" width="360" height="8" as="geometry"/>
        </mxCell>
        <mxCell id="103" value="+ register_domain(domain: str): bool&#xa;+ add_reference_logo(img_bytes: bytes): str" style="text;strokeColor=none;fillColor=none;align=left;verticalAlign=top;spacingLeft=4;spacingRight=4;overflow=hidden;rotatable=0;points=[[0,0.5],[1,0.5]];portConstraint=eastwest;fontColor=#38bdf8;" vertex="1" parent="100">
          <mxGeometry y="98" width="360" height="52" as="geometry"/>
        </mxCell>

        <mxCell id="110" value="DomainProber" style="swimlane;fontStyle=1;align=center;verticalAlign=top;childLayout=stackLayout;horizontal=1;startSize=26;horizontalStack=0;resizeParent=1;resizeParentMax=0;resizeLast=0;collapsible=1;marginBottom=0;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#38bdf8;" vertex="1" parent="1">
          <mxGeometry x="80" y="380" width="360" height="230" as="geometry"/>
        </mxCell>
        <mxCell id="111" value="- doh_resolvers: List[str]&#xa;- request_timeout: float = 8.0&#xa;- idna_codec: str = 'punycode'" style="text;strokeColor=none;fillColor=none;align=left;verticalAlign=top;spacingLeft=4;spacingRight=4;overflow=hidden;rotatable=0;points=[[0,0.5],[1,0.5]];portConstraint=eastwest;fontColor=#cbd5e1;" vertex="1" parent="110">
          <mxGeometry y="26" width="360" height="54" as="geometry"/>
        </mxCell>
        <mxCell id="112" value="" style="line;strokeWidth=1;fillColor=none;align=left;verticalAlign=middle;spacingTop=-1;spacingLeft=3;spacingRight=3;rotatable=0;labelPosition=right;points=[];portConstraint=eastwest;strokeColor=#334155;" vertex="1" parent="110">
          <mxGeometry y="80" width="360" height="8" as="geometry"/>
        </mxCell>
        <mxCell id="113" value="+ clean_domain_string(raw: str): str&#xa;+ generate_permutations(domain: str): List[str]&#xa;+ resolve_doh_dns(domain: str): Dict&#xa;+ query_rdap_whois(domain: str): Dict&#xa;+ extract_ssl_x509(host: str, port: int): Dict&#xa;+ evaluate_domain_risk(perm: str, base: str): float" style="text;strokeColor=none;fillColor=none;align=left;verticalAlign=top;spacingLeft=4;spacingRight=4;overflow=hidden;rotatable=0;points=[[0,0.5],[1,0.5]];portConstraint=eastwest;fontColor=#38bdf8;" vertex="1" parent="110">
          <mxGeometry y="88" width="360" height="132" as="geometry"/>
        </mxCell>

        <mxCell id="120" value="HeterogeneousThreatGraph" style="swimlane;fontStyle=1;align=center;verticalAlign=top;childLayout=stackLayout;horizontal=1;startSize=26;horizontalStack=0;resizeParent=1;resizeParentMax=0;resizeLast=0;collapsible=1;marginBottom=0;html=1;fillColor=#1e293b;strokeColor=#a855f7;fontColor=#a855f7;" vertex="1" parent="1">
          <mxGeometry x="1150" y="160" width="440" height="220" as="geometry"/>
        </mxCell>
        <mxCell id="121" value="- nodes: Dict[str, EntityNode]&#xa;- edges: List[RelationEdge]&#xa;- graph_engine: NetworkX.Graph" style="text;strokeColor=none;fillColor=none;align=left;verticalAlign=top;spacingLeft=4;spacingRight=4;overflow=hidden;rotatable=0;points=[[0,0.5],[1,0.5]];portConstraint=eastwest;fontColor=#cbd5e1;" vertex="1" parent="120">
          <mxGeometry y="26" width="440" height="54" as="geometry"/>
        </mxCell>
        <mxCell id="122" value="" style="line;strokeWidth=1;fillColor=none;align=left;verticalAlign=middle;spacingTop=-1;spacingLeft=3;spacingRight=3;rotatable=0;labelPosition=right;points=[];portConstraint=eastwest;strokeColor=#334155;" vertex="1" parent="120">
          <mxGeometry y="80" width="440" height="8" as="geometry"/>
        </mxCell>
        <mxCell id="123" value="+ insert_entity(id: str, type: str, props: Dict): EntityNode&#xa;+ insert_relation(src: str, dst: str, rel: str, w: float): bool&#xa;+ compute_degree_centrality(): Dict[str, float]&#xa;+ compute_betweenness_centrality(): Dict[str, float]&#xa;+ isolate_syndicate_clusters(): List[Set[str]]&#xa;+ export_cytoscape_json(): Dict" style="text;strokeColor=none;fillColor=none;align=left;verticalAlign=top;spacingLeft=4;spacingRight=4;overflow=hidden;rotatable=0;points=[[0,0.5],[1,0.5]];portConstraint=eastwest;fontColor=#a855f7;" vertex="1" parent="120">
          <mxGeometry y="88" width="440" height="122" as="geometry"/>
        </mxCell>
"""
with open(OUT_DIR / "02_CLASS_DIAGRAM.drawio", "w", encoding="utf-8") as f:
    f.write(wrap_drawio("diag_class", "UML Class Diagram", xml_2, 1700, 1200))

print("Diagram 2 completed.")

print("Preparing Diagram 3: UML Sequence Diagram...")
# -------------------------------------------------------------
# 3. SEQUENCE DIAGRAM
# -------------------------------------------------------------
svg_3 = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1760 1250" width="100%" height="100%" style="background:#090d16; font-family:'Segoe UI', Inter, -apple-system, sans-serif;">
  <defs>
    <linearGradient id="bgHeader3" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#4f46e5"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
    <filter id="shadow3" x="-5%" y="-5%" width="110%" height="110%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.5"/>
    </filter>
    <marker id="seqArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>
    </marker>
    <marker id="seqReturn" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981"/>
    </marker>
  </defs>

  <!-- Title Banner -->
  <rect x="40" y="30" width="1680" height="70" rx="10" fill="url(#bgHeader3)" filter="url(#shadow3)"/>
  <text x="880" y="65" text-anchor="middle" fill="#ffffff" font-size="22" font-weight="bold" letter-spacing="1">UML SEQUENCE DIAGRAM: END-TO-END MULTI-VECTOR INVESTIGATION LIFECYCLE</text>
  <text x="880" y="88" text-anchor="middle" fill="#e0e7ff" font-size="13">Chronological Message Flow Across Distributed Probers, Forensic Analyzers, Knowledge Graph, NIST Custody Vault, and Takedown Dispatch</text>

  <!-- LIFELINES & HEADERS -->
  <!-- 1. Analyst -->
  <rect x="50" y="130" width="140" height="50" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5"/>
  <text x="120" y="160" text-anchor="middle" fill="#38bdf8" font-size="12" font-weight="bold">:SOC Analyst</text>
  <line x1="120" y1="180" x2="120" y2="1150" stroke="#334155" stroke-width="1.5" stroke-dasharray="5,5"/>

  <!-- 2. UI Workbench -->
  <rect x="230" y="130" width="150" height="50" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5"/>
  <text x="305" y="160" text-anchor="middle" fill="#38bdf8" font-size="12" font-weight="bold">:ThreatWorkbench</text>
  <line x1="305" y1="180" x2="305" y2="1150" stroke="#334155" stroke-width="1.5" stroke-dasharray="5,5"/>

  <!-- 3. Gateway / Orchestrator -->
  <rect x="420" y="130" width="160" height="50" rx="8" fill="#1e293b" stroke="#818cf8" stroke-width="1.5"/>
  <text x="500" y="160" text-anchor="middle" fill="#818cf8" font-size="12" font-weight="bold">:InvestigationOrch</text>
  <line x1="500" y1="180" x2="500" y2="1150" stroke="#334155" stroke-width="1.5" stroke-dasharray="5,5"/>

  <!-- 4. Active Probers -->
  <rect x="620" y="130" width="160" height="50" rx="8" fill="#1e293b" stroke="#06b6d4" stroke-width="1.5"/>
  <text x="700" y="160" text-anchor="middle" fill="#06b6d4" font-size="12" font-weight="bold">:NetworkProbers</text>
  <line x1="700" y1="180" x2="700" y2="1150" stroke="#334155" stroke-width="1.5" stroke-dasharray="5,5"/>

  <!-- 5. Forensic Engines -->
  <rect x="820" y="130" width="160" height="50" rx="8" fill="#1e293b" stroke="#06b6d4" stroke-width="1.5"/>
  <text x="900" y="160" text-anchor="middle" fill="#06b6d4" font-size="12" font-weight="bold">:ForensicEngines</text>
  <line x1="900" y1="180" x2="900" y2="1150" stroke="#334155" stroke-width="1.5" stroke-dasharray="5,5"/>

  <!-- 6. Threat Graph -->
  <rect x="1020" y="130" width="150" height="50" rx="8" fill="#1e293b" stroke="#a855f7" stroke-width="1.5"/>
  <text x="1095" y="160" text-anchor="middle" fill="#a855f7" font-size="12" font-weight="bold">:ThreatGraph</text>
  <line x1="1095" y1="180" x2="1095" y2="1150" stroke="#334155" stroke-width="1.5" stroke-dasharray="5,5"/>

  <!-- 7. Risk Engine -->
  <rect x="1210" y="130" width="150" height="50" rx="8" fill="#1e293b" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="1285" y="160" text-anchor="middle" fill="#f59e0b" font-size="12" font-weight="bold">:RiskEngine</text>
  <line x1="1285" y1="180" x2="1285" y2="1150" stroke="#334155" stroke-width="1.5" stroke-dasharray="5,5"/>

  <!-- 8. Evidence Vault (NIST) -->
  <rect x="1400" y="130" width="150" height="50" rx="8" fill="#1e293b" stroke="#10b981" stroke-width="1.5"/>
  <text x="1475" y="160" text-anchor="middle" fill="#10b981" font-size="12" font-weight="bold">:EvidenceVault</text>
  <line x1="1475" y1="180" x2="1475" y2="1150" stroke="#334155" stroke-width="1.5" stroke-dasharray="5,5"/>

  <!-- 9. Remediation Studio -->
  <rect x="1590" y="130" width="150" height="50" rx="8" fill="#1e293b" stroke="#f43f5e" stroke-width="1.5"/>
  <text x="1665" y="160" text-anchor="middle" fill="#f43f5e" font-size="12" font-weight="bold">:TakedownStudio</text>
  <line x1="1665" y1="180" x2="1665" y2="1150" stroke="#334155" stroke-width="1.5" stroke-dasharray="5,5"/>

  <!-- ACTIVATION BOXES & MESSAGES -->
  <!-- 1. Analyst -> UI -->
  <line x1="120" y1="210" x2="305" y2="210" stroke="#38bdf8" stroke-width="1.8" marker-end="url(#seqArrow)"/>
  <text x="212" y="202" text-anchor="middle" fill="#e0f2fe" font-size="11">1: Submit Target Domain &amp; Brand</text>

  <!-- 2. UI -> Gateway -->
  <line x1="305" y1="240" x2="500" y2="240" stroke="#38bdf8" stroke-width="1.8" marker-end="url(#seqArrow)"/>
  <text x="402" y="232" text-anchor="middle" fill="#e0f2fe" font-size="11">2: POST /api/scan/deep</text>

  <!-- 3. Gateway -> Probers -->
  <line x1="500" y1="270" x2="700" y2="270" stroke="#06b6d4" stroke-width="1.8" marker-end="url(#seqArrow)"/>
  <text x="600" y="262" text-anchor="middle" fill="#06b6d4" font-size="11">3: dispatch_probes(domain, brand)</text>

  <!-- PARALLEL BLOCK 1: Active Probing -->
  <rect x="610" y="290" width="370" height="150" rx="6" fill="#0f172a" stroke="#06b6d4" stroke-dasharray="4,4" fill-opacity="0.6"/>
  <rect x="610" y="290" width="50" height="20" fill="#082f49"/>
  <text x="635" y="304" text-anchor="middle" fill="#38bdf8" font-size="10" font-weight="bold">par</text>
  
  <line x1="700" y1="320" x2="740" y2="320" stroke="#06b6d4" stroke-width="1.5"/>
  <line x1="740" y1="320" x2="740" y2="335" stroke="#06b6d4" stroke-width="1.5"/>
  <line x1="740" y1="335" x2="700" y2="335" stroke="#06b6d4" stroke-width="1.5" marker-end="url(#seqArrow)"/>
  <text x="750" y="332" fill="#94a3b8" font-size="10">4a: Resolve DoH DNS &amp; RDAP Whois</text>

  <line x1="700" y1="360" x2="740" y2="360" stroke="#06b6d4" stroke-width="1.5"/>
  <line x1="740" y1="360" x2="740" y2="375" stroke="#06b6d4" stroke-width="1.5"/>
  <line x1="740" y1="375" x2="700" y2="375" stroke="#06b6d4" stroke-width="1.5" marker-end="url(#seqArrow)"/>
  <text x="750" y="372" fill="#94a3b8" font-size="10">4b: Perform TLS Handshake &amp; Extract X.509</text>

  <line x1="700" y1="400" x2="740" y2="400" stroke="#06b6d4" stroke-width="1.5"/>
  <line x1="740" y1="400" x2="740" y2="415" stroke="#06b6d4" stroke-width="1.5"/>
  <line x1="740" y1="415" x2="700" y2="415" stroke="#06b6d4" stroke-width="1.5" marker-end="url(#seqArrow)"/>
  <text x="750" y="412" fill="#94a3b8" font-size="10">4c: Crawl HTML DOM &amp; Render Viewport Image</text>

  <!-- Probers -> Gateway Return -->
  <line x1="700" y1="460" x2="500" y2="460" stroke="#10b981" stroke-width="1.8" stroke-dasharray="4,4" marker-end="url(#seqReturn)"/>
  <text x="600" y="452" text-anchor="middle" fill="#10b981" font-size="11">5: Network Telemetry &amp; Raw Artifacts</text>

  <!-- Gateway -> Forensics -->
  <line x1="500" y1="490" x2="900" y2="490" stroke="#818cf8" stroke-width="1.8" marker-end="url(#seqArrow)"/>
  <text x="700" y="482" text-anchor="middle" fill="#e0e7ff" font-size="11">6: execute_multimodal_forensics(telemetry)</text>

  <!-- PARALLEL BLOCK 2: Forensic Analysis -->
  <rect x="810" y="510" width="370" height="150" rx="6" fill="#0f172a" stroke="#818cf8" stroke-dasharray="4,4" fill-opacity="0.6"/>
  <rect x="810" y="510" width="50" height="20" fill="#1e1b4b"/>
  <text x="835" y="524" text-anchor="middle" fill="#818cf8" font-size="10" font-weight="bold">par</text>

  <line x1="900" y1="540" x2="940" y2="540" stroke="#818cf8" stroke-width="1.5"/>
  <line x1="940" y1="540" x2="940" y2="555" stroke="#818cf8" stroke-width="1.5"/>
  <line x1="940" y1="555" x2="900" y2="555" stroke="#818cf8" stroke-width="1.5" marker-end="url(#seqArrow)"/>
  <text x="950" y="552" fill="#94a3b8" font-size="10">7a: Compute 64-bit pHash &amp; CIELAB Distance</text>

  <line x1="900" y1="580" x2="940" y2="580" stroke="#818cf8" stroke-width="1.5"/>
  <line x1="940" y1="580" x2="940" y2="595" stroke="#818cf8" stroke-width="1.5"/>
  <line x1="940" y1="595" x2="900" y2="595" stroke="#818cf8" stroke-width="1.5" marker-end="url(#seqArrow)"/>
  <text x="950" y="592" fill="#94a3b8" font-size="10">7b: Strip Zero-Width Spaces &amp; Match Urgency NLP</text>

  <line x1="900" y1="620" x2="940" y2="620" stroke="#818cf8" stroke-width="1.5"/>
  <line x1="940" y1="620" x2="940" y2="635" stroke="#818cf8" stroke-width="1.5"/>
  <line x1="940" y1="635" x2="900" y2="635" stroke="#818cf8" stroke-width="1.5" marker-end="url(#seqArrow)"/>
  <text x="950" y="632" fill="#94a3b8" font-size="10">7c: Audit RFC 7208 SPF &amp; Form Action C2 Webhooks</text>

  <!-- Forensics -> Gateway Return -->
  <line x1="900" y1="680" x2="500" y2="680" stroke="#10b981" stroke-width="1.8" stroke-dasharray="4,4" marker-end="url(#seqReturn)"/>
  <text x="700" y="672" text-anchor="middle" fill="#10b981" font-size="11">8: Forensic Vector Scores {S_domain, S_visual, S_nlp, ...}</text>

  <!-- Gateway -> ThreatGraph -->
  <line x1="500" y1="710" x2="1095" y2="710" stroke="#a855f7" stroke-width="1.8" marker-end="url(#seqArrow)"/>
  <text x="797" y="702" text-anchor="middle" fill="#a855f7" font-size="11">9: insert_entities_and_build_edges(features)</text>

  <line x1="1095" y1="735" x2="1135" y2="735" stroke="#a855f7" stroke-width="1.5"/>
  <line x1="1135" y1="735" x2="1135" y2="750" stroke="#a855f7" stroke-width="1.5"/>
  <line x1="1135" y1="750" x2="1095" y2="750" stroke="#a855f7" stroke-width="1.5" marker-end="url(#seqArrow)"/>
  <text x="1145" y="747" fill="#94a3b8" font-size="10">10: Compute Degree/Betweenness Centrality &amp; Communities</text>

  <line x1="1095" y1="775" x2="500" y2="775" stroke="#10b981" stroke-width="1.8" stroke-dasharray="4,4" marker-end="url(#seqReturn)"/>
  <text x="797" y="767" text-anchor="middle" fill="#10b981" font-size="11">11: Graph Metrics &amp; Syndicate Cluster Identifiers</text>

  <!-- Gateway -> RiskEngine -->
  <line x1="500" y1="810" x2="1285" y2="810" stroke="#f59e0b" stroke-width="1.8" marker-end="url(#seqArrow)"/>
  <text x="892" y="802" text-anchor="middle" fill="#f59e0b" font-size="11">12: calculate_composite_risk(vector_scores, graph_metrics)</text>

  <line x1="1285" y1="835" x2="1325" y2="835" stroke="#f59e0b" stroke-width="1.5"/>
  <line x1="1325" y1="835" x2="1325" y2="850" stroke="#f59e0b" stroke-width="1.5"/>
  <line x1="1325" y1="850" x2="1285" y2="850" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#seqArrow)"/>
  <text x="1335" y="847" fill="#94a3b8" font-size="10">13: Apply Linear Weights + Non-Linear Adversarial Synergy</text>

  <line x1="1285" y1="875" x2="500" y2="875" stroke="#10b981" stroke-width="1.8" stroke-dasharray="4,4" marker-end="url(#seqReturn)"/>
  <text x="892" y="867" text-anchor="middle" fill="#10b981" font-size="11">14: Composite Risk Score (R=94, Tier=CRITICAL, XAI Attribution)</text>

  <!-- Gateway -> EvidenceVault (NIST SP 800-86) -->
  <line x1="500" y1="910" x2="1475" y2="910" stroke="#10b981" stroke-width="1.8" marker-end="url(#seqArrow)"/>
  <text x="987" y="902" text-anchor="middle" fill="#10b981" font-size="11">15: seal_evidence_artifact(raw_bytes, target_uri, metadata)</text>

  <line x1="1475" y1="935" x2="1515" y2="935" stroke="#10b981" stroke-width="1.5"/>
  <line x1="1515" y1="935" x2="1515" y2="950" stroke="#10b981" stroke-width="1.5"/>
  <line x1="1515" y1="950" x2="1475" y2="950" stroke="#10b981" stroke-width="1.5" marker-end="url(#seqArrow)"/>
  <text x="1525" y="947" fill="#94a3b8" font-size="10">16: Compute SHA-256 + SHA3-512 &amp; HMAC-SHA256 Digital Seal</text>

  <line x1="1475" y1="975" x2="500" y2="975" stroke="#10b981" stroke-width="1.8" stroke-dasharray="4,4" marker-end="url(#seqReturn)"/>
  <text x="987" y="967" text-anchor="middle" fill="#10b981" font-size="11">17: Sealed Block Receipt (Index #125, Previous Hash, Block Hash)</text>

  <!-- ALTERNATIVE BLOCK: Automated Remediation -->
  <rect x="440" y="1000" width="1280" height="90" rx="6" fill="#0f172a" stroke="#f43f5e" stroke-dasharray="4,4" fill-opacity="0.6"/>
  <rect x="440" y="1000" width="50" height="20" fill="#4c0519"/>
  <text x="465" y="1014" text-anchor="middle" fill="#f43f5e" font-size="10" font-weight="bold">alt</text>
  <text x="500" y="1014" fill="#f43f5e" font-size="10">[Composite Risk Score &gt;= 80 or Tier == CRITICAL]</text>

  <line x1="500" y1="1040" x2="1665" y2="1040" stroke="#f43f5e" stroke-width="1.8" marker-end="url(#seqArrow)"/>
  <text x="1082" y="1032" text-anchor="middle" fill="#f43f5e" font-size="11">18: generate_icann_abuse_notice &amp; compile_stix21_bundle(incident)</text>

  <line x1="1665" y1="1070" x2="500" y2="1070" stroke="#10b981" stroke-width="1.8" stroke-dasharray="4,4" marker-end="url(#seqReturn)"/>
  <text x="1082" y="1062" text-anchor="middle" fill="#10b981" font-size="11">19: Formatted ICANN RAA §3.18 Abuse Dossier &amp; STIX 2.1 Threat Intel</text>

  <!-- Final Return to UI and Analyst -->
  <line x1="500" y1="1110" x2="305" y2="1110" stroke="#10b981" stroke-width="2" stroke-dasharray="4,4" marker-end="url(#seqReturn)"/>
  <text x="402" y="1102" text-anchor="middle" fill="#10b981" font-size="11">20: 200 OK (Full Dossier, Cytoscape JSON, Custody Receipts)</text>

  <line x1="305" y1="1140" x2="120" y2="1140" stroke="#10b981" stroke-width="2" stroke-dasharray="4,4" marker-end="url(#seqReturn)"/>
  <text x="212" y="1132" text-anchor="middle" fill="#10b981" font-size="11">21: Render HUD, Interactive Graph Canvas &amp; Actionable Takedown</text>
</svg>"""

with open(OUT_DIR / "03_SEQUENCE_DIAGRAM.svg", "w", encoding="utf-8") as f:
    f.write(svg_3)

xml_3 = """
        <mxCell id="200" value="SOC Analyst" style="shape=umlLifeline;perimeter=lifelinePerimeter;whiteSpace=wrap;html=1;container=1;collapsible=0;recursiveResize=0;outlineConnect=0;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#38bdf8;" vertex="1" parent="1">
          <mxGeometry x="80" y="140" width="100" height="900" as="geometry"/>
        </mxCell>
        <mxCell id="201" value="ThreatWorkbench" style="shape=umlLifeline;perimeter=lifelinePerimeter;whiteSpace=wrap;html=1;container=1;collapsible=0;recursiveResize=0;outlineConnect=0;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#38bdf8;" vertex="1" parent="1">
          <mxGeometry x="260" y="140" width="120" height="900" as="geometry"/>
        </mxCell>
        <mxCell id="202" value="InvestigationOrch" style="shape=umlLifeline;perimeter=lifelinePerimeter;whiteSpace=wrap;html=1;container=1;collapsible=0;recursiveResize=0;outlineConnect=0;fillColor=#1e293b;strokeColor=#818cf8;fontColor=#818cf8;" vertex="1" parent="1">
          <mxGeometry x="460" y="140" width="120" height="900" as="geometry"/>
        </mxCell>
        <mxCell id="203" value="NetworkProbers" style="shape=umlLifeline;perimeter=lifelinePerimeter;whiteSpace=wrap;html=1;container=1;collapsible=0;recursiveResize=0;outlineConnect=0;fillColor=#1e293b;strokeColor=#06b6d4;fontColor=#06b6d4;" vertex="1" parent="1">
          <mxGeometry x="660" y="140" width="120" height="900" as="geometry"/>
        </mxCell>
        <mxCell id="204" value="ForensicEngines" style="shape=umlLifeline;perimeter=lifelinePerimeter;whiteSpace=wrap;html=1;container=1;collapsible=0;recursiveResize=0;outlineConnect=0;fillColor=#1e293b;strokeColor=#06b6d4;fontColor=#06b6d4;" vertex="1" parent="1">
          <mxGeometry x="860" y="140" width="120" height="900" as="geometry"/>
        </mxCell>
        <mxCell id="205" value="ThreatGraph" style="shape=umlLifeline;perimeter=lifelinePerimeter;whiteSpace=wrap;html=1;container=1;collapsible=0;recursiveResize=0;outlineConnect=0;fillColor=#1e293b;strokeColor=#a855f7;fontColor=#a855f7;" vertex="1" parent="1">
          <mxGeometry x="1060" y="140" width="120" height="900" as="geometry"/>
        </mxCell>
        <mxCell id="206" value="RiskEngine" style="shape=umlLifeline;perimeter=lifelinePerimeter;whiteSpace=wrap;html=1;container=1;collapsible=0;recursiveResize=0;outlineConnect=0;fillColor=#1e293b;strokeColor=#f59e0b;fontColor=#f59e0b;" vertex="1" parent="1">
          <mxGeometry x="1260" y="140" width="120" height="900" as="geometry"/>
        </mxCell>
        <mxCell id="207" value="EvidenceVault" style="shape=umlLifeline;perimeter=lifelinePerimeter;whiteSpace=wrap;html=1;container=1;collapsible=0;recursiveResize=0;outlineConnect=0;fillColor=#1e293b;strokeColor=#10b981;fontColor=#10b981;" vertex="1" parent="1">
          <mxGeometry x="1460" y="140" width="120" height="900" as="geometry"/>
        </mxCell>

        <mxCell id="210" value="1: Submit Target Domain" style="html=1;verticalAlign=bottom;endArrow=block;strokeColor=#38bdf8;fontColor=#e0f2fe;" edge="1" parent="1" source="200" target="201">
          <mxGeometry relative="1" as="geometry"><mxPoint y="210" as="offset"/></mxGeometry>
        </mxCell>
        <mxCell id="211" value="2: POST /api/scan/deep" style="html=1;verticalAlign=bottom;endArrow=block;strokeColor=#38bdf8;fontColor=#e0f2fe;" edge="1" parent="1" source="201" target="202">
          <mxGeometry relative="1" as="geometry"><mxPoint y="240" as="offset"/></mxGeometry>
        </mxCell>
        <mxCell id="212" value="3: dispatch_probes()" style="html=1;verticalAlign=bottom;endArrow=block;strokeColor=#06b6d4;fontColor=#06b6d4;" edge="1" parent="1" source="202" target="203">
          <mxGeometry relative="1" as="geometry"><mxPoint y="270" as="offset"/></mxGeometry>
        </mxCell>
        <mxCell id="213" value="5: Raw Telemetry" style="html=1;verticalAlign=bottom;endArrow=open;dashed=1;endSize=8;strokeColor=#10b981;fontColor=#10b981;" edge="1" parent="1" source="203" target="202">
          <mxGeometry relative="1" as="geometry"><mxPoint y="370" as="offset"/></mxGeometry>
        </mxCell>
        <mxCell id="214" value="6: execute_multimodal_forensics()" style="html=1;verticalAlign=bottom;endArrow=block;strokeColor=#818cf8;fontColor=#e0e7ff;" edge="1" parent="1" source="202" target="204">
          <mxGeometry relative="1" as="geometry"><mxPoint y="410" as="offset"/></mxGeometry>
        </mxCell>
        <mxCell id="215" value="8: Forensic Scores" style="html=1;verticalAlign=bottom;endArrow=open;dashed=1;endSize=8;strokeColor=#10b981;fontColor=#10b981;" edge="1" parent="1" source="204" target="202">
          <mxGeometry relative="1" as="geometry"><mxPoint y="510" as="offset"/></mxGeometry>
        </mxCell>
        <mxCell id="216" value="9: insert_entities_and_build_edges()" style="html=1;verticalAlign=bottom;endArrow=block;strokeColor=#a855f7;fontColor=#a855f7;" edge="1" parent="1" source="202" target="205">
          <mxGeometry relative="1" as="geometry"><mxPoint y="550" as="offset"/></mxGeometry>
        </mxCell>
        <mxCell id="217" value="12: calculate_composite_risk()" style="html=1;verticalAlign=bottom;endArrow=block;strokeColor=#f59e0b;fontColor=#f59e0b;" edge="1" parent="1" source="202" target="206">
          <mxGeometry relative="1" as="geometry"><mxPoint y="650" as="offset"/></mxGeometry>
        </mxCell>
        <mxCell id="218" value="15: seal_evidence_artifact()" style="html=1;verticalAlign=bottom;endArrow=block;strokeColor=#10b981;fontColor=#10b981;" edge="1" parent="1" source="202" target="207">
          <mxGeometry relative="1" as="geometry"><mxPoint y="750" as="offset"/></mxGeometry>
        </mxCell>
"""
with open(OUT_DIR / "03_SEQUENCE_DIAGRAM.drawio", "w", encoding="utf-8") as f:
    f.write(wrap_drawio("diag_seq", "UML Sequence Diagram", xml_3, 1760, 1250))

print("Diagram 3 completed.")

print("Preparing Diagram 4: UML Activity / Action Diagram...")
# -------------------------------------------------------------
# 4. ACTIVITY DIAGRAM
# -------------------------------------------------------------
svg_4 = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 1350" width="100%" height="100%" style="background:#090d16; font-family:'Segoe UI', Inter, -apple-system, sans-serif;">
  <defs>
    <linearGradient id="bgHeader4" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#4f46e5"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
    <filter id="shadow4" x="-5%" y="-5%" width="110%" height="110%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.5"/>
    </filter>
    <marker id="actArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>
    </marker>
  </defs>

  <!-- Title Banner -->
  <rect x="40" y="30" width="1520" height="70" rx="10" fill="url(#bgHeader4)" filter="url(#shadow4)"/>
  <text x="800" y="65" text-anchor="middle" fill="#ffffff" font-size="22" font-weight="bold" letter-spacing="1">UML ACTIVITY &amp; ACTION FLOW DIAGRAM: INVESTIGATION PIPELINE</text>
  <text x="800" y="88" text-anchor="middle" fill="#e0e7ff" font-size="13">Control Flow Modeling Ingestion Forks, Parallel Multi-Vector Probing, Graph Correlation, Risk Decisions, and Custody Joins</text>

  <!-- START NODE -->
  <circle cx="800" cy="140" r="16" fill="#38bdf8" stroke="#ffffff" stroke-width="3"/>
  
  <line x1="800" y1="156" x2="800" y2="185" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- Action 1: Ingestion -->
  <rect x="620" y="185" width="360" height="46" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" filter="url(#shadow4)"/>
  <text x="800" y="213" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Ingest Target URI / Domain &amp; Brand Reference</text>

  <line x1="800" y1="231" x2="800" y2="260" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- Action 2: Sanitization -->
  <rect x="600" y="260" width="400" height="46" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" filter="url(#shadow4)"/>
  <text x="800" y="288" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Sanitize Domain (Strip control bytes, normalize IDN Punycode)</text>

  <line x1="800" y1="306" x2="800" y2="340" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- FORK BAR (Thick black/indigo bar) -->
  <rect x="100" y="340" width="1400" height="12" rx="4" fill="#6366f1"/>
  <text x="1510" y="350" fill="#818cf8" font-size="11" font-weight="bold">&lt;&lt;fork&gt;&gt;</text>

  <!-- FORK BRANCHES (6 Parallel Paths) -->
  <!-- Branch 1: DNS & RDAP -->
  <line x1="200" y1="352" x2="200" y2="390" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>
  <rect x="90" y="390" width="220" height="70" rx="8" fill="#082f49" stroke="#0ea5e9" stroke-width="1.5" filter="url(#shadow4)"/>
  <text x="200" y="418" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Resolve DoH DNS &amp;</text>
  <text x="200" y="434" text-anchor="middle" fill="#7dd3fc" font-size="10">RDAP Whois Metadata</text>
  <line x1="200" y1="460" x2="200" y2="530" stroke="#38bdf8" stroke-width="2"/>

  <!-- Branch 2: TLS X.509 -->
  <line x1="440" y1="352" x2="440" y2="390" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>
  <rect x="330" y="390" width="220" height="70" rx="8" fill="#082f49" stroke="#0ea5e9" stroke-width="1.5" filter="url(#shadow4)"/>
  <text x="440" y="418" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Perform TLS Handshake &amp;</text>
  <text x="440" y="434" text-anchor="middle" fill="#7dd3fc" font-size="10">Extract X.509 Certificate</text>
  <line x1="440" y1="460" x2="440" y2="530" stroke="#38bdf8" stroke-width="2"/>

  <!-- Branch 3: Visual Screenshot & pHash -->
  <line x1="680" y1="352" x2="680" y2="390" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>
  <rect x="570" y="390" width="220" height="70" rx="8" fill="#1e1b4b" stroke="#6366f1" stroke-width="1.5" filter="url(#shadow4)"/>
  <text x="680" y="418" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Capture Viewport &amp;</text>
  <text x="680" y="434" text-anchor="middle" fill="#a5b4fc" font-size="10">Compute 64-bit DCT pHash</text>
  <line x1="680" y1="460" x2="680" y2="530" stroke="#38bdf8" stroke-width="2"/>

  <!-- Branch 4: Form Action & C2 Webhooks -->
  <line x1="920" y1="352" x2="920" y2="390" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>
  <rect x="810" y="390" width="220" height="70" rx="8" fill="#1e1b4b" stroke="#6366f1" stroke-width="1.5" filter="url(#shadow4)"/>
  <text x="920" y="418" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Inspect Form Actions &amp;</text>
  <text x="920" y="434" text-anchor="middle" fill="#a5b4fc" font-size="10">Detect Telegram/Discord C2</text>
  <line x1="920" y1="460" x2="920" y2="530" stroke="#38bdf8" stroke-width="2"/>

  <!-- Branch 5: RFC 7208 SPF / RFC 7489 DMARC -->
  <line x1="1160" y1="352" x2="1160" y2="390" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>
  <rect x="1050" y="390" width="220" height="70" rx="8" fill="#082f49" stroke="#0ea5e9" stroke-width="1.5" filter="url(#shadow4)"/>
  <text x="1160" y="418" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Audit Email Protocols</text>
  <text x="1160" y="434" text-anchor="middle" fill="#7dd3fc" font-size="10">(RFC 7208 SPF / DMARC)</text>
  <line x1="1160" y1="460" x2="1160" y2="530" stroke="#38bdf8" stroke-width="2"/>

  <!-- Branch 6: Social Recon & Phone E.164 -->
  <line x1="1400" y1="352" x2="1400" y2="390" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>
  <rect x="1290" y="390" width="220" height="70" rx="8" fill="#082f49" stroke="#0ea5e9" stroke-width="1.5" filter="url(#shadow4)"/>
  <text x="1400" y="418" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Social Handle Recon &amp;</text>
  <text x="1400" y="434" text-anchor="middle" fill="#7dd3fc" font-size="10">E.164 Carrier Spoof Check</text>
  <line x1="1400" y1="460" x2="1400" y2="530" stroke="#38bdf8" stroke-width="2"/>

  <!-- JOIN BAR (Thick black/indigo bar) -->
  <rect x="100" y="530" width="1400" height="12" rx="4" fill="#6366f1"/>
  <text x="1510" y="540" fill="#818cf8" font-size="11" font-weight="bold">&lt;&lt;join&gt;&gt;</text>

  <line x1="800" y1="542" x2="800" y2="575" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- Action 3: Threat Graph Correlation -->
  <rect x="580" y="575" width="440" height="50" rx="8" fill="#3b0764" stroke="#a855f7" stroke-width="1.8" filter="url(#shadow4)"/>
  <text x="800" y="605" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Correlate Entities into Heterogeneous Threat Graph</text>

  <line x1="800" y1="625" x2="800" y2="655" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- Action 4: Centrality Analysis -->
  <rect x="580" y="655" width="440" height="50" rx="8" fill="#3b0764" stroke="#a855f7" stroke-width="1.8" filter="url(#shadow4)"/>
  <text x="800" y="685" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Compute Degree / Betweenness Centrality &amp; Syndicate Clusters</text>

  <line x1="800" y1="705" x2="800" y2="735" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- Action 5: Calibrated Risk Engine -->
  <rect x="560" y="735" width="480" height="50" rx="8" fill="#451a03" stroke="#f59e0b" stroke-width="1.8" filter="url(#shadow4)"/>
  <text x="800" y="765" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Compute Calibrated Risk Score &amp; Apply Synergy Multipliers</text>

  <line x1="800" y1="785" x2="800" y2="815" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- Action 6: NIST SP 800-86 Evidence Sealing -->
  <rect x="560" y="815" width="480" height="50" rx="8" fill="#064e3b" stroke="#10b981" stroke-width="1.8" filter="url(#shadow4)"/>
  <text x="800" y="845" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Seal Artifacts into NIST SP 800-86 Immutable Hash Chain</text>

  <line x1="800" y1="865" x2="800" y2="900" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- DECISION DIAMOND: Risk >= 60? -->
  <polygon points="800,900 900,945 800,990 700,945" fill="#1e293b" stroke="#f59e0b" stroke-width="2" filter="url(#shadow4)"/>
  <text x="800" y="942" text-anchor="middle" fill="#f59e0b" font-size="11" font-weight="bold">Risk Score &gt;= 60</text>
  <text x="800" y="955" text-anchor="middle" fill="#94a3b8" font-size="10">(Actionable Threat?)</text>

  <!-- Decision Branch 1: [Yes / Actionable High or Critical] (Right) -->
  <line x1="900" y1="945" x2="1140" y2="945" stroke="#f43f5e" stroke-width="2" marker-end="url(#actArrow)"/>
  <text x="960" y="935" fill="#f43f5e" font-size="11" font-weight="bold">[Yes: High/Critical]</text>

  <rect x="1140" y="915" width="360" height="60" rx="8" fill="#4c0519" stroke="#f43f5e" stroke-width="1.8" filter="url(#shadow4)"/>
  <text x="1320" y="940" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Auto-Generate ICANN RAA §3.18 Notice &amp;</text>
  <text x="1320" y="956" text-anchor="middle" fill="#fda4af" font-size="10">STIX 2.1 Threat Intel Bundle</text>

  <line x1="1320" y1="975" x2="1320" y2="1080" stroke="#f43f5e" stroke-width="2"/>
  <line x1="1320" y1="1080" x2="830" y2="1080" stroke="#f43f5e" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- Decision Branch 2: [No / Low or Benign] (Down) -->
  <line x1="800" y1="990" x2="800" y2="1025" stroke="#10b981" stroke-width="2" marker-end="url(#actArrow)"/>
  <text x="815" y="1010" fill="#10b981" font-size="11" font-weight="bold">[No: Benign/Low]</text>

  <rect x="620" y="1025" width="360" height="40" rx="8" fill="#064e3b" stroke="#10b981" stroke-width="1.5" filter="url(#shadow4)"/>
  <text x="800" y="1050" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Archive Telemetry &amp; Enroll in 24h Watchlist</text>

  <!-- MERGE NODE -->
  <polygon points="800,1070 825,1080 800,1090 775,1080" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5"/>

  <line x1="800" y1="1090" x2="800" y2="1120" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- Action 7: Render UI HUD -->
  <rect x="600" y="1120" width="400" height="46" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" filter="url(#shadow4)"/>
  <text x="800" y="1148" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">Render Cytoscape Threat Canvas &amp; XAI Attribution</text>

  <line x1="800" y1="1166" x2="800" y2="1200" stroke="#38bdf8" stroke-width="2" marker-end="url(#actArrow)"/>

  <!-- FINAL NODE (Circle with inner solid circle) -->
  <circle cx="800" cy="1220" r="18" fill="#0f172a" stroke="#38bdf8" stroke-width="2.5"/>
  <circle cx="800" cy="1220" r="10" fill="#38bdf8"/>
</svg>"""

with open(OUT_DIR / "04_ACTIVITY_DIAGRAM.svg", "w", encoding="utf-8") as f:
    f.write(svg_4)

xml_4 = """
        <mxCell id="300" value="" style="ellipse;html=1;shape=startState;fillColor=#38bdf8;strokeColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="785" y="140" width="30" height="30" as="geometry"/>
        </mxCell>
        <mxCell id="301" value="Ingest Target URI / Domain &amp; Brand Context" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="640" y="190" width="320" height="40" as="geometry"/>
        </mxCell>
        <mxCell id="302" value="Sanitize Domain (Control bytes, Punycode)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="640" y="250" width="320" height="40" as="geometry"/>
        </mxCell>
        <mxCell id="303" value="" style="line;strokeWidth=6;fillColor=none;align=left;verticalAlign=middle;strokeColor=#6366f1;" vertex="1" parent="1">
          <mxGeometry x="200" y="320" width="1200" height="10" as="geometry"/>
        </mxCell>
        <mxCell id="304" value="Resolve DoH DNS &amp; RDAP" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#082f49;strokeColor=#0ea5e9;fontColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="220" y="360" width="200" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="305" value="Extract TLS X.509 Cert" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#082f49;strokeColor=#0ea5e9;fontColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="460" y="360" width="200" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="306" value="Compute 64-bit DCT pHash" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e1b4b;strokeColor=#6366f1;fontColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="700" y="360" width="200" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="307" value="Audit Form Action C2 Webhooks" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e1b4b;strokeColor=#6366f1;fontColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="940" y="360" width="200" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="308" value="Audit RFC 7208 SPF / DMARC" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#082f49;strokeColor=#0ea5e9;fontColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="1180" y="360" width="200" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="309" value="" style="line;strokeWidth=6;fillColor=none;align=left;verticalAlign=middle;strokeColor=#6366f1;" vertex="1" parent="1">
          <mxGeometry x="200" y="450" width="1200" height="10" as="geometry"/>
        </mxCell>
        <mxCell id="310" value="Correlate Entities in Threat Graph" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#3b0764;strokeColor=#a855f7;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="640" y="490" width="320" height="40" as="geometry"/>
        </mxCell>
        <mxCell id="311" value="Compute Calibrated Composite Risk &amp; Synergy" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#451a03;strokeColor=#f59e0b;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="620" y="560" width="360" height="40" as="geometry"/>
        </mxCell>
        <mxCell id="312" value="Seal Artifacts in NIST SP 800-86 Ledger" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#064e3b;strokeColor=#10b981;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="620" y="630" width="360" height="40" as="geometry"/>
        </mxCell>
        <mxCell id="313" value="Risk &gt;= 60?" style="rhombus;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#f59e0b;fontColor=#f59e0b;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="720" y="700" width="160" height="80" as="geometry"/>
        </mxCell>
        <mxCell id="314" value="Auto-Generate ICANN Notice &amp; STIX 2.1" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#4c0519;strokeColor=#f43f5e;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="960" y="720" width="280" height="40" as="geometry"/>
        </mxCell>
        <mxCell id="315" value="" style="ellipse;html=1;shape=endState;fillColor=#0f172a;strokeColor=#38bdf8;" vertex="1" parent="1">
          <mxGeometry x="785" y="880" width="30" height="30" as="geometry"/>
        </mxCell>
"""
with open(OUT_DIR / "04_ACTIVITY_DIAGRAM.drawio", "w", encoding="utf-8") as f:
    f.write(wrap_drawio("diag_activity", "UML Activity Diagram", xml_4, 1600, 1350))

print("Diagram 4 completed.")

print("Preparing Diagram 5: UML State Machine / State Space Diagram...")
# -------------------------------------------------------------
# 5. STATE MACHINE DIAGRAM
# -------------------------------------------------------------
svg_5 = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 1250" width="100%" height="100%" style="background:#090d16; font-family:'Segoe UI', Inter, -apple-system, sans-serif;">
  <defs>
    <linearGradient id="bgHeader5" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#4f46e5"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
    <filter id="shadow5" x="-5%" y="-5%" width="110%" height="110%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.5"/>
    </filter>
    <marker id="stateArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>
    </marker>
    <marker id="critArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e"/>
    </marker>
    <marker id="benignArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981"/>
    </marker>
  </defs>

  <!-- Title Banner -->
  <rect x="40" y="30" width="1520" height="70" rx="10" fill="url(#bgHeader5)" filter="url(#shadow5)"/>
  <text x="800" y="65" text-anchor="middle" fill="#ffffff" font-size="22" font-weight="bold" letter-spacing="1">UML STATE MACHINE &amp; STATE SPACE DIAGRAM: INCIDENT THREAT LIFECYCLE</text>
  <text x="800" y="88" text-anchor="middle" fill="#e0e7ff" font-size="13">State Transitions, Composite States, Guard Conditions, Threat Tiers, and NIST Evidentiary Lifecycle</text>

  <!-- Initial State -->
  <circle cx="100" cy="200" r="16" fill="#38bdf8" stroke="#ffffff" stroke-width="3"/>
  <line x1="116" y1="200" x2="160" y2="200" stroke="#38bdf8" stroke-width="2" marker-end="url(#stateArrow)"/>

  <!-- State 1: DORMANT_BASELINE -->
  <g transform="translate(160, 160)">
    <rect x="0" y="0" width="240" height="80" rx="10" fill="#1e293b" stroke="#38bdf8" stroke-width="1.8" filter="url(#shadow5)"/>
    <text x="120" y="28" text-anchor="middle" fill="#38bdf8" font-size="12" font-weight="bold">DORMANT_BASELINE</text>
    <line x1="0" y1="38" x2="240" y2="38" stroke="#334155"/>
    <text x="12" y="55" fill="#94a3b8" font-size="10">entry / monitor_brand_assets()</text>
    <text x="12" y="70" fill="#94a3b8" font-size="10">do / poll_certificate_transparency()</text>
  </g>

  <!-- Transition 1 -> 2 -->
  <line x1="400" y1="200" x2="490" y2="200" stroke="#38bdf8" stroke-width="2" marker-end="url(#stateArrow)"/>
  <text x="445" y="190" text-anchor="middle" fill="#7dd3fc" font-size="10">signal_detected</text>

  <!-- State 2: DISCOVERED -->
  <g transform="translate(490, 160)">
    <rect x="0" y="0" width="220" height="80" rx="10" fill="#1e293b" stroke="#818cf8" stroke-width="1.8" filter="url(#shadow5)"/>
    <text x="110" y="28" text-anchor="middle" fill="#818cf8" font-size="12" font-weight="bold">SIGNAL_DISCOVERED</text>
    <line x1="0" y1="38" x2="220" y2="38" stroke="#334155"/>
    <text x="12" y="55" fill="#94a3b8" font-size="10">entry / queue_target_domain()</text>
    <text x="12" y="70" fill="#94a3b8" font-size="10">do / sanitize_idn_punycode()</text>
  </g>

  <!-- Transition 2 -> Composite 1 -->
  <line x1="710" y1="200" x2="800" y2="200" stroke="#38bdf8" stroke-width="2" marker-end="url(#stateArrow)"/>
  <text x="755" y="190" text-anchor="middle" fill="#7dd3fc" font-size="10">dispatch_probes</text>

  <!-- COMPOSITE STATE 1: ACTIVE_RECONNAISSANCE -->
  <g transform="translate(800, 130)">
    <rect x="0" y="0" width="750" height="150" rx="14" fill="#0f172a" stroke="#06b6d4" stroke-width="2" filter="url(#shadow5)"/>
    <text x="25" y="25" fill="#06b6d4" font-size="12" font-weight="bold">COMPOSITE STATE: ACTIVE_RECONNAISSANCE</text>

    <!-- Substate 1 -->
    <rect x="25" y="45" width="220" height="85" rx="8" fill="#1e293b" stroke="#0ea5e9"/>
    <text x="135" y="70" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">DNS_RDAP_QUERYING</text>
    <text x="35" y="90" fill="#94a3b8" font-size="9">do / query_doh_resolvers()</text>
    <text x="35" y="105" fill="#94a3b8" font-size="9">do / extract_asn_whois()</text>

    <!-- Substate 2 -->
    <rect x="265" y="45" width="220" height="85" rx="8" fill="#1e293b" stroke="#0ea5e9"/>
    <text x="375" y="70" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">TLS_HANDSHAKE_EXTRACT</text>
    <text x="275" y="90" fill="#94a3b8" font-size="9">do / parse_x509_cert()</text>
    <text x="275" y="105" fill="#94a3b8" font-size="9">do / extract_san_alt_names()</text>

    <!-- Substate 3 -->
    <rect x="505" y="45" width="220" height="85" rx="8" fill="#1e293b" stroke="#0ea5e9"/>
    <text x="615" y="70" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">DOM_CRAWL_AND_SCREENSHOT</text>
    <text x="515" y="90" fill="#94a3b8" font-size="9">do / headless_viewport_render()</text>
    <text x="515" y="105" fill="#94a3b8" font-size="9">do / extract_form_actions()</text>
  </g>

  <!-- Transition Composite 1 -> Composite 2 -->
  <line x1="1175" y1="280" x2="1175" y2="350" stroke="#38bdf8" stroke-width="2" marker-end="url(#stateArrow)"/>
  <text x="1185" y="320" fill="#7dd3fc" font-size="10">telemetry_ready</text>

  <!-- COMPOSITE STATE 2: MULTIMODAL_FORENSICS -->
  <g transform="translate(800, 350)">
    <rect x="0" y="0" width="750" height="150" rx="14" fill="#0f172a" stroke="#818cf8" stroke-width="2" filter="url(#shadow5)"/>
    <text x="25" y="25" fill="#818cf8" font-size="12" font-weight="bold">COMPOSITE STATE: MULTIMODAL_FORENSIC_ANALYSIS</text>

    <!-- Substate 1 -->
    <rect x="25" y="45" width="220" height="85" rx="8" fill="#1e293b" stroke="#818cf8"/>
    <text x="135" y="70" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">LOGO_PHASH_MATCHING</text>
    <text x="35" y="90" fill="#94a3b8" font-size="9">do / 64bit_dct_phash()</text>
    <text x="35" y="105" fill="#94a3b8" font-size="9">do / cielab_histogram_match()</text>

    <!-- Substate 2 -->
    <rect x="265" y="45" width="220" height="85" rx="8" fill="#1e293b" stroke="#818cf8"/>
    <text x="375" y="70" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">NLP_LURE_INSPECTION</text>
    <text x="275" y="90" fill="#94a3b8" font-size="9">do / strip_zero_width_spaces()</text>
    <text x="275" y="105" fill="#94a3b8" font-size="9">do / score_urgency_triggers()</text>

    <!-- Substate 3 -->
    <rect x="505" y="45" width="220" height="85" rx="8" fill="#1e293b" stroke="#818cf8"/>
    <text x="615" y="70" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">PROTOCOL_COMPLIANCE</text>
    <text x="515" y="90" fill="#94a3b8" font-size="9">do / parse_rfc7208_spf()</text>
    <text x="515" y="105" fill="#94a3b8" font-size="9">do / audit_rfc7489_dmarc()</text>
  </g>

  <!-- Transition Composite 2 -> State 3 (Leftwards flow) -->
  <line x1="800" y1="425" x2="650" y2="425" stroke="#38bdf8" stroke-width="2" marker-end="url(#stateArrow)"/>
  <text x="725" y="415" text-anchor="middle" fill="#7dd3fc" font-size="10">features_extracted</text>

  <!-- State 3: GRAPH_CORRELATING -->
  <g transform="translate(380, 385)">
    <rect x="0" y="0" width="270" height="80" rx="10" fill="#1e293b" stroke="#a855f7" stroke-width="1.8" filter="url(#shadow5)"/>
    <text x="135" y="28" text-anchor="middle" fill="#a855f7" font-size="12" font-weight="bold">GRAPH_CORRELATING</text>
    <line x1="0" y1="38" x2="270" y2="38" stroke="#334155"/>
    <text x="12" y="55" fill="#94a3b8" font-size="10">entry / update_knowledge_graph()</text>
    <text x="12" y="70" fill="#94a3b8" font-size="10">do / compute_centrality_and_clusters()</text>
  </g>

  <!-- Transition 3 -> 4 (Downwards flow) -->
  <line x1="515" y1="465" x2="515" y2="540" stroke="#38bdf8" stroke-width="2" marker-end="url(#stateArrow)"/>
  <text x="525" y="505" fill="#7dd3fc" font-size="10">topology_resolved</text>

  <!-- State 4: RISK_EVALUATING -->
  <g transform="translate(380, 540)">
    <rect x="0" y="0" width="270" height="85" rx="10" fill="#1e293b" stroke="#f59e0b" stroke-width="1.8" filter="url(#shadow5)"/>
    <text x="135" y="28" text-anchor="middle" fill="#f59e0b" font-size="12" font-weight="bold">RISK_EVALUATING</text>
    <line x1="0" y1="38" x2="270" y2="38" stroke="#334155"/>
    <text x="12" y="55" fill="#94a3b8" font-size="10">entry / calculate_linear_weights()</text>
    <text x="12" y="70" fill="#94a3b8" font-size="10">do / apply_adversarial_synergy()</text>
  </g>

  <!-- Transition 4 -> 5 -->
  <line x1="650" y1="582" x2="800" y2="582" stroke="#38bdf8" stroke-width="2" marker-end="url(#stateArrow)"/>
  <text x="725" y="572" text-anchor="middle" fill="#7dd3fc" font-size="10">score_finalized</text>

  <!-- State 5: EVIDENCE_SEALING (NIST SP 800-86) -->
  <g transform="translate(800, 540)">
    <rect x="0" y="0" width="300" height="85" rx="10" fill="#1e293b" stroke="#10b981" stroke-width="2" filter="url(#shadow5)"/>
    <text x="150" y="28" text-anchor="middle" fill="#10b981" font-size="12" font-weight="bold">EVIDENCE_CUSTODY_SEALING</text>
    <line x1="0" y1="38" x2="300" y2="38" stroke="#334155"/>
    <text x="12" y="55" fill="#94a3b8" font-size="10">entry / dual_hash(SHA256, SHA3-512)</text>
    <text x="12" y="70" fill="#94a3b8" font-size="10">do / append_immutable_ledger_block()</text>
  </g>

  <!-- GUARD BRANCHES (From Evidence Sealing to Tiers) -->
  <!-- 1. [Score >= 80] -> ACTIONABLE_CRITICAL -->
  <line x1="950" y1="625" x2="950" y2="700" stroke="#f43f5e" stroke-width="2.5" marker-end="url(#critArrow)"/>
  <text x="960" y="665" fill="#f43f5e" font-size="11" font-weight="bold">[Score &gt;= 80 (CRITICAL)]</text>

  <g transform="translate(800, 700)">
    <rect x="0" y="0" width="300" height="85" rx="10" fill="#4c0519" stroke="#f43f5e" stroke-width="2" filter="url(#shadow5)"/>
    <text x="150" y="28" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">ACTIONABLE_CRITICAL</text>
    <line x1="0" y1="38" x2="300" y2="38" stroke="#f43f5e"/>
    <text x="12" y="55" fill="#fda4af" font-size="10">entry / auto_generate_icann_notice()</text>
    <text x="12" y="70" fill="#fda4af" font-size="10">do / dispatch_registrar_abuse_packet()</text>
  </g>

  <!-- Transition -> TAKEDOWN_SUBMITTED -->
  <line x1="950" y1="785" x2="950" y2="860" stroke="#f43f5e" stroke-width="2" marker-end="url(#critArrow)"/>
  <text x="960" y="825" fill="#f43f5e" font-size="10">notice_dispatched</text>

  <g transform="translate(800, 860)">
    <rect x="0" y="0" width="300" height="75" rx="10" fill="#1e293b" stroke="#f43f5e" stroke-width="1.8" filter="url(#shadow5)"/>
    <text x="150" y="28" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">TAKEDOWN_SUBMITTED</text>
    <line x1="0" y1="38" x2="300" y2="38" stroke="#334155"/>
    <text x="12" y="55" fill="#94a3b8" font-size="10">do / poll_dns_suspension_status()</text>
  </g>

  <!-- Transition -> NEUTRALIZED_RESOLVED -->
  <line x1="950" y1="935" x2="950" y2="1010" stroke="#10b981" stroke-width="2" marker-end="url(#benignArrow)"/>
  <text x="960" y="975" fill="#10b981" font-size="10">domain_suspended_or_sinkholed</text>

  <g transform="translate(800, 1010)">
    <rect x="0" y="0" width="300" height="60" rx="10" fill="#064e3b" stroke="#10b981" stroke-width="2" filter="url(#shadow5)"/>
    <text x="150" y="26" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">NEUTRALIZED_RESOLVED</text>
    <text x="150" y="44" text-anchor="middle" fill="#a7f3d0" font-size="10">exit / close_incident_record()</text>
  </g>

  <!-- Final Node (Resolved) -->
  <circle cx="950" cy="1130" r="18" fill="#0f172a" stroke="#10b981" stroke-width="2.5"/>
  <circle cx="950" cy="1130" r="10" fill="#10b981"/>
  <line x1="950" y1="1070" x2="950" y2="1112" stroke="#10b981" stroke-width="2" marker-end="url(#benignArrow)"/>

  <!-- 2. [60 <= Score < 80] -> HIGH_RISK_REVIEW (Left branch) -->
  <line x1="800" y1="590" x2="250" y2="590" stroke="#f59e0b" stroke-width="2"/>
  <line x1="250" y1="590" x2="250" y2="700" stroke="#f59e0b" stroke-width="2" marker-end="url(#stateArrow)"/>
  <text x="260" y="650" fill="#f59e0b" font-size="10" font-weight="bold">[60 &lt;= Score &lt; 80]</text>

  <g transform="translate(100, 700)">
    <rect x="0" y="0" width="280" height="85" rx="10" fill="#451a03" stroke="#f59e0b" stroke-width="1.8" filter="url(#shadow5)"/>
    <text x="140" y="28" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">HIGH_RISK_MANUAL_REVIEW</text>
    <line x1="0" y1="38" x2="280" y2="38" stroke="#f59e0b"/>
    <text x="12" y="55" fill="#fde68a" font-size="10">entry / alert_soc_analyst_queue()</text>
    <text x="12" y="70" fill="#fde68a" font-size="10">do / inspect_xai_attribution()</text>
  </g>

  <!-- 3. [20 <= Score < 60] -> SUSPICIOUS_MONITORED -->
  <line x1="1100" y1="582" x2="1350" y2="582" stroke="#38bdf8" stroke-width="2"/>
  <line x1="1350" y1="582" x2="1350" y2="700" stroke="#38bdf8" stroke-width="2" marker-end="url(#stateArrow)"/>
  <text x="1360" y="650" fill="#38bdf8" font-size="10" font-weight="bold">[20 &lt;= Score &lt; 60]</text>

  <g transform="translate(1220, 700)">
    <rect x="0" y="0" width="260" height="85" rx="10" fill="#082f49" stroke="#38bdf8" stroke-width="1.8" filter="url(#shadow5)"/>
    <text x="130" y="28" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">SUSPICIOUS_MONITORED</text>
    <line x1="0" y1="38" x2="260" y2="38" stroke="#38bdf8"/>
    <text x="12" y="55" fill="#7dd3fc" font-size="10">entry / add_to_24h_watchlist()</text>
    <text x="12" y="70" fill="#7dd3fc" font-size="10">do / schedule_differential_reprobe()</text>
  </g>

  <!-- Re-probe Loop from Suspicious back to Active Reconnaissance -->
  <path d="M 1480 740 L 1570 740 L 1570 200 L 1550 200" stroke="#38bdf8" stroke-width="1.8" stroke-dasharray="4,4" marker-end="url(#stateArrow)"/>
  <text x="1560" y="470" fill="#38bdf8" font-size="10" transform="rotate(90,1560,470)">24h_timer_expired</text>

  <!-- 4. [Score < 20] -> BENIGN_DISMISSED -->
  <line x1="1100" y1="560" x2="1480" y2="560" stroke="#10b981" stroke-width="1.8"/>
  <line x1="1480" y1="560" x2="1480" y2="860" stroke="#10b981" stroke-width="1.8" marker-end="url(#benignArrow)"/>
  <text x="1490" y="610" fill="#10b981" font-size="10" font-weight="bold">[Score &lt; 20 (BENIGN)]</text>

  <g transform="translate(1360, 860)">
    <rect x="0" y="0" width="220" height="60" rx="10" fill="#064e3b" stroke="#10b981" stroke-width="1.8" filter="url(#shadow5)"/>
    <text x="110" y="26" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">BENIGN_DISMISSED</text>
    <text x="110" y="44" text-anchor="middle" fill="#a7f3d0" font-size="9">entry / archive_evidence_receipt()</text>
  </g>

  <!-- Final Node (Benign) -->
  <circle cx="1470" cy="980" r="16" fill="#0f172a" stroke="#10b981" stroke-width="2.5"/>
  <circle cx="1470" cy="980" r="9" fill="#10b981"/>
  <line x1="1470" y1="920" x2="1470" y2="964" stroke="#10b981" stroke-width="1.8" marker-end="url(#benignArrow)"/>
</svg>"""

with open(OUT_DIR / "05_STATE_MACHINE_DIAGRAM.svg", "w", encoding="utf-8") as f:
    f.write(svg_5)

xml_5 = """
        <mxCell id="400" value="" style="ellipse;html=1;shape=startState;fillColor=#38bdf8;strokeColor=#ffffff;" vertex="1" parent="1">
          <mxGeometry x="80" y="180" width="30" height="30" as="geometry"/>
        </mxCell>
        <mxCell id="401" value="DORMANT_BASELINE&#xa;entry / monitor_brand_assets()&#xa;do / poll_ct_logs()" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="160" y="160" width="220" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="402" value="SIGNAL_DISCOVERED&#xa;entry / queue_target_domain()&#xa;do / sanitize_idn_punycode()" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#818cf8;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="460" y="160" width="220" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="403" value="ACTIVE_RECONNAISSANCE&#xa;(DNS, RDAP, TLS X.509, DOM)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#082f49;strokeColor=#0ea5e9;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="760" y="160" width="280" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="404" value="MULTIMODAL_FORENSICS&#xa;(pHash, Urgency NLP, SPF/DMARC)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e1b4b;strokeColor=#6366f1;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="760" y="290" width="280" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="405" value="GRAPH_CORRELATING&#xa;entry / update_threat_graph()&#xa;do / compute_centrality()" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#3b0764;strokeColor=#a855f7;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="440" y="290" width="240" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="406" value="RISK_EVALUATING&#xa;entry / linear_weights()&#xa;do / apply_synergy_bonuses()" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#451a03;strokeColor=#f59e0b;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="440" y="420" width="240" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="407" value="EVIDENCE_CUSTODY_SEALING&#xa;entry / dual_hash(SHA256, SHA3)&#xa;do / append_ledger_block()" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#064e3b;strokeColor=#10b981;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="760" y="420" width="280" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="408" value="ACTIONABLE_CRITICAL&#xa;[Score &gt;= 80]&#xa;do / auto_generate_takedown()" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#4c0519;strokeColor=#f43f5e;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="760" y="550" width="280" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="409" value="TAKEDOWN_SUBMITTED&#xa;do / poll_dns_suspension()" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#f43f5e;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="760" y="680" width="280" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="410" value="" style="ellipse;html=1;shape=endState;fillColor=#0f172a;strokeColor=#10b981;" vertex="1" parent="1">
          <mxGeometry x="885" y="810" width="30" height="30" as="geometry"/>
        </mxCell>
"""
with open(OUT_DIR / "05_STATE_MACHINE_DIAGRAM.drawio", "w", encoding="utf-8") as f:
    f.write(wrap_drawio("diag_state", "UML State Machine Diagram", xml_5, 1600, 1250))

print("Diagram 5 completed.")

print("Preparing Diagram 6: Cross-Functional Swimlane Diagram...")
# -------------------------------------------------------------
# 6. SWIMLANE DIAGRAM
# -------------------------------------------------------------
svg_6 = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1700 1300" width="100%" height="100%" style="background:#090d16; font-family:'Segoe UI', Inter, -apple-system, sans-serif;">
  <defs>
    <linearGradient id="bgHeader6" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#4f46e5"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
    <filter id="shadow6" x="-5%" y="-5%" width="110%" height="110%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.5"/>
    </filter>
    <marker id="swimArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>
    </marker>
    <marker id="critSwim" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e"/>
    </marker>
  </defs>

  <!-- Title Banner -->
  <rect x="40" y="30" width="1620" height="70" rx="10" fill="url(#bgHeader6)" filter="url(#shadow6)"/>
  <text x="850" y="65" text-anchor="middle" fill="#ffffff" font-size="22" font-weight="bold" letter-spacing="1">CROSS-FUNCTIONAL SWIMLANE DIAGRAM: INVESTIGATION &amp; REMEDIATION WORKFLOW</text>
  <text x="850" y="88" text-anchor="middle" fill="#e0e7ff" font-size="13">Functional Separation Across Data Ingestion, AI Forensics, Threat Graph Correlation &amp; Custody, and SOC Legal Operations</text>

  <!-- SWIMLANE BOUNDARY (4 Vertical Lanes) -->
  <rect x="50" y="130" width="1600" height="1120" rx="14" fill="#0f172a" stroke="#334155" stroke-width="2" filter="url(#shadow6)"/>

  <!-- Lane 1: Ingestion & Network Recon -->
  <rect x="50" y="130" width="380" height="1120" rx="14" fill="#082f49" fill-opacity="0.15" stroke="#334155"/>
  <rect x="50" y="130" width="380" height="45" rx="14" fill="#1e293b"/>
  <text x="240" y="158" text-anchor="middle" fill="#38bdf8" font-size="13" font-weight="bold">LANE 1: DATA INGESTION &amp; RECON</text>

  <!-- Lane 2: AI & Multi-Modal Forensics -->
  <rect x="430" y="130" width="410" height="1120" fill="#1e1b4b" fill-opacity="0.15" stroke="#334155"/>
  <rect x="430" y="130" width="410" height="45" fill="#1e293b"/>
  <text x="635" y="158" text-anchor="middle" fill="#818cf8" font-size="13" font-weight="bold">LANE 2: AI &amp; MULTI-MODAL FORENSICS</text>

  <!-- Lane 3: Threat Correlation & Risk -->
  <rect x="840" y="130" width="410" height="1120" fill="#3b0764" fill-opacity="0.15" stroke="#334155"/>
  <rect x="840" y="130" width="410" height="45" fill="#1e293b"/>
  <text x="1045" y="158" text-anchor="middle" fill="#a855f7" font-size="13" font-weight="bold">LANE 3: THREAT CORRELATION &amp; RISK</text>

  <!-- Lane 4: SOC Operations & Remediation -->
  <rect x="1250" y="130" width="400" height="1120" rx="14" fill="#4c0519" fill-opacity="0.15" stroke="#334155"/>
  <rect x="1250" y="130" width="400" height="45" rx="14" fill="#1e293b"/>
  <text x="1450" y="158" text-anchor="middle" fill="#f43f5e" font-size="13" font-weight="bold">LANE 4: SOC OPERATIONS &amp; TAKEDOWN</text>

  <!-- LANE 1 NODES -->
  <!-- Start Node -->
  <circle cx="240" cy="210" r="14" fill="#38bdf8" stroke="#ffffff" stroke-width="2.5"/>
  <line x1="240" y1="224" x2="240" y2="255" stroke="#38bdf8" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- Step 1 -->
  <rect x="90" y="255" width="300" height="50" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" filter="url(#shadow6)"/>
  <text x="240" y="285" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Poll CT Logs &amp; Ingest Watchlist Targets</text>

  <line x1="240" y1="305" x2="240" y2="340" stroke="#38bdf8" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- Step 2 -->
  <rect x="90" y="340" width="300" height="50" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" filter="url(#shadow6)"/>
  <text x="240" y="370" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Generate IDN Punycode &amp; Typosquats</text>

  <line x1="240" y1="390" x2="240" y2="425" stroke="#38bdf8" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- Step 3 -->
  <rect x="90" y="425" width="300" height="50" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" filter="url(#shadow6)"/>
  <text x="240" y="455" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Execute Live DoH DNS &amp; RDAP Whois Probes</text>

  <line x1="240" y1="475" x2="240" y2="510" stroke="#38bdf8" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- Step 4 -->
  <rect x="90" y="510" width="300" height="50" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" filter="url(#shadow6)"/>
  <text x="240" y="535" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Crawl DOM, Capture Viewport Screenshot,</text>
  <text x="240" y="550" text-anchor="middle" fill="#7dd3fc" font-size="10">&amp; Extract Form Action Destinations</text>

  <!-- Cross-Lane Transition 1 -> 2 -->
  <line x1="390" y1="535" x2="480" y2="535" stroke="#818cf8" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- LANE 2 NODES -->
  <!-- Step 5 -->
  <rect x="480" y="510" width="310" height="50" rx="8" fill="#1e293b" stroke="#818cf8" stroke-width="1.5" filter="url(#shadow6)"/>
  <text x="635" y="535" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Compute 64-bit DCT pHash &amp; dHash</text>
  <text x="635" y="550" text-anchor="middle" fill="#a5b4fc" font-size="10">Match Logo against Brand Reference Database</text>

  <line x1="635" y1="560" x2="635" y2="595" stroke="#818cf8" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- Step 6 -->
  <rect x="480" y="595" width="310" height="50" rx="8" fill="#1e293b" stroke="#818cf8" stroke-width="1.5" filter="url(#shadow6)"/>
  <text x="635" y="620" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Strip Zero-Width Spaces &amp; Parse NLP</text>
  <text x="635" y="635" text-anchor="middle" fill="#a5b4fc" font-size="10">Calculate Urgency, Action &amp; Credential Cues</text>

  <line x1="635" y1="645" x2="635" y2="680" stroke="#818cf8" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- Step 7 -->
  <rect x="480" y="680" width="310" height="50" rx="8" fill="#1e293b" stroke="#818cf8" stroke-width="1.5" filter="url(#shadow6)"/>
  <text x="635" y="705" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Audit RFC 7208 SPF &amp; RFC 7489 DMARC</text>
  <text x="635" y="720" text-anchor="middle" fill="#a5b4fc" font-size="10">Detect Anti-Cloaking &amp; Telegram/Discord C2</text>

  <!-- Cross-Lane Transition 2 -> 3 -->
  <line x1="790" y1="705" x2="890" y2="705" stroke="#a855f7" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- LANE 3 NODES -->
  <!-- Step 8 -->
  <rect x="890" y="680" width="310" height="50" rx="8" fill="#1e293b" stroke="#a855f7" stroke-width="1.5" filter="url(#shadow6)"/>
  <text x="1045" y="705" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Correlate Entities in Threat Knowledge Graph</text>
  <text x="1045" y="720" text-anchor="middle" fill="#d8b4fe" font-size="10">Compute Degree / Betweenness Centrality</text>

  <line x1="1045" y1="730" x2="1045" y2="765" stroke="#a855f7" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- Step 9 -->
  <rect x="890" y="765" width="310" height="50" rx="8" fill="#1e293b" stroke="#f59e0b" stroke-width="1.5" filter="url(#shadow6)"/>
  <text x="1045" y="790" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Compute Calibrated Composite Risk Score</text>
  <text x="1045" y="805" text-anchor="middle" fill="#fde68a" font-size="10">Apply Multi-Vector Adversarial Synergy Multipliers</text>

  <line x1="1045" y1="815" x2="1045" y2="850" stroke="#f59e0b" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- Step 10 -->
  <rect x="890" y="850" width="310" height="50" rx="8" fill="#1e293b" stroke="#10b981" stroke-width="1.8" filter="url(#shadow6)"/>
  <text x="1045" y="875" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Seal Artifacts in NIST SP 800-86 Ledger</text>
  <text x="1045" y="890" text-anchor="middle" fill="#a7f3d0" font-size="10">Dual SHA-256 + SHA3 Hash Chain &amp; HMAC Seal</text>

  <!-- Cross-Lane Transition 3 -> 4 -->
  <line x1="1200" y1="875" x2="1290" y2="875" stroke="#f43f5e" stroke-width="2" marker-end="url(#critSwim)"/>

  <!-- LANE 4 NODES -->
  <!-- Step 11 -->
  <rect x="1290" y="850" width="320" height="50" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" filter="url(#shadow6)"/>
  <text x="1450" y="875" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Render Live Incident on Threat HUD</text>
  <text x="1450" y="890" text-anchor="middle" fill="#7dd3fc" font-size="10">Interactive Cytoscape Graph &amp; XAI Attribution</text>

  <line x1="1450" y1="900" x2="1450" y2="935" stroke="#f43f5e" stroke-width="2" marker-end="url(#critSwim)"/>

  <!-- Decision: Actionable Takedown? -->
  <polygon points="1450,935 1530,975 1450,1015 1370,975" fill="#1e293b" stroke="#f59e0b" stroke-width="1.8" filter="url(#shadow6)"/>
  <text x="1450" y="972" text-anchor="middle" fill="#f59e0b" font-size="10" font-weight="bold">Risk &gt;= 80?</text>
  <text x="1450" y="985" text-anchor="middle" fill="#94a3b8" font-size="9">(Actionable?)</text>

  <!-- Branch [Yes]: Takedown Dispatch -->
  <line x1="1450" y1="1015" x2="1450" y2="1050" stroke="#f43f5e" stroke-width="2" marker-end="url(#critSwim)"/>
  <text x="1465" y="1035" fill="#f43f5e" font-size="10" font-weight="bold">[Yes: High/Crit]</text>

  <rect x="1290" y="1050" width="320" height="60" rx="8" fill="#4c0519" stroke="#f43f5e" stroke-width="1.8" filter="url(#shadow6)"/>
  <text x="1450" y="1075" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">Auto-Generate ICANN RAA §3.18 Notice &amp;</text>
  <text x="1450" y="1092" text-anchor="middle" fill="#fda4af" font-size="10">Export OASIS STIX 2.1 Threat Intel Bundle</text>

  <line x1="1450" y1="1110" x2="1450" y2="1150" stroke="#10b981" stroke-width="2" marker-end="url(#swimArrow)"/>

  <!-- Final Node -->
  <circle cx="1450" cy="1170" r="18" fill="#0f172a" stroke="#10b981" stroke-width="2.5"/>
  <circle cx="1450" cy="1170" r="10" fill="#10b981"/>

  <!-- Branch [No]: Watchlist -->
  <path d="M 1370 975 L 1260 975 L 1260 370 L 390 370" stroke="#38bdf8" stroke-width="1.8" stroke-dasharray="4,4" marker-end="url(#swimArrow)"/>
  <text x="1245" y="965" text-anchor="end" fill="#38bdf8" font-size="10">[No: Add to 24h Watchlist]</text>
</svg>"""

with open(OUT_DIR / "06_SWIMLANE_DIAGRAM.svg", "w", encoding="utf-8") as f:
    f.write(svg_6)

xml_6 = """
        <mxCell id="500" value="LANE 1: DATA INGESTION &amp; RECON" style="swimlane;startSize=30;html=1;fillColor=#082f49;strokeColor=#38bdf8;fontColor=#38bdf8;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="80" y="140" width="360" height="980" as="geometry"/>
        </mxCell>
        <mxCell id="501" value="LANE 2: AI &amp; MULTI-MODAL FORENSICS" style="swimlane;startSize=30;html=1;fillColor=#1e1b4b;strokeColor=#818cf8;fontColor=#818cf8;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="440" y="140" width="380" height="980" as="geometry"/>
        </mxCell>
        <mxCell id="502" value="LANE 3: THREAT CORRELATION &amp; RISK" style="swimlane;startSize=30;html=1;fillColor=#3b0764;strokeColor=#a855f7;fontColor=#a855f7;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="820" y="140" width="380" height="980" as="geometry"/>
        </mxCell>
        <mxCell id="503" value="LANE 4: SOC OPERATIONS &amp; TAKEDOWN" style="swimlane;startSize=30;html=1;fillColor=#4c0519;strokeColor=#f43f5e;fontColor=#f43f5e;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="1200" y="140" width="380" height="980" as="geometry"/>
        </mxCell>

        <mxCell id="510" value="Poll CT Logs &amp; Ingest Targets" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#ffffff;" vertex="1" parent="500">
          <mxGeometry x="40" y="80" width="280" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="511" value="Generate Punycode Permutations" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#ffffff;" vertex="1" parent="500">
          <mxGeometry x="40" y="170" width="280" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="512" value="Execute DoH DNS &amp; RDAP Probes" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#ffffff;" vertex="1" parent="500">
          <mxGeometry x="40" y="260" width="280" height="50" as="geometry"/>
        </mxCell>

        <mxCell id="520" value="Compute 64-bit DCT pHash &amp; dHash" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#818cf8;fontColor=#ffffff;" vertex="1" parent="501">
          <mxGeometry x="40" y="350" width="300" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="521" value="Strip Zero-Width &amp; Score NLP Urgency" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#818cf8;fontColor=#ffffff;" vertex="1" parent="501">
          <mxGeometry x="40" y="440" width="300" height="50" as="geometry"/>
        </mxCell>

        <mxCell id="530" value="Correlate Entities in Threat Graph" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#a855f7;fontColor=#ffffff;" vertex="1" parent="502">
          <mxGeometry x="40" y="530" width="300" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="531" value="Compute Calibrated Risk &amp; Synergy" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#f59e0b;fontColor=#ffffff;" vertex="1" parent="502">
          <mxGeometry x="40" y="620" width="300" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="532" value="Seal Artifacts in NIST Hash Chain" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#10b981;fontColor=#ffffff;" vertex="1" parent="502">
          <mxGeometry x="40" y="710" width="300" height="50" as="geometry"/>
        </mxCell>

        <mxCell id="540" value="Render HUD &amp; Cytoscape Canvas" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#ffffff;" vertex="1" parent="503">
          <mxGeometry x="40" y="800" width="300" height="50" as="geometry"/>
        </mxCell>
        <mxCell id="541" value="Auto-Generate ICANN Notice &amp; STIX 2.1" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#4c0519;strokeColor=#f43f5e;fontColor=#ffffff;" vertex="1" parent="503">
          <mxGeometry x="40" y="890" width="300" height="50" as="geometry"/>
        </mxCell>
"""
with open(OUT_DIR / "06_SWIMLANE_DIAGRAM.drawio", "w", encoding="utf-8") as f:
    f.write(wrap_drawio("diag_swimlane", "Cross-Functional Swimlane Diagram", xml_6, 1700, 1300))

print("Diagram 6 completed.")

print("Preparing Diagram 7: Entity-Relationship Diagram (ERD)...")
# -------------------------------------------------------------
# 7. ENTITY-RELATIONSHIP DIAGRAM
# -------------------------------------------------------------
svg_7 = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1760 1350" width="100%" height="100%" style="background:#090d16; font-family:'Segoe UI', Inter, -apple-system, sans-serif;">
  <defs>
    <linearGradient id="bgHeader7" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#4f46e5"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
    <filter id="shadow7" x="-5%" y="-5%" width="110%" height="110%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.5"/>
    </filter>
  </defs>

  <!-- Title Banner -->
  <rect x="40" y="30" width="1680" height="70" rx="10" fill="url(#bgHeader7)" filter="url(#shadow7)"/>
  <text x="880" y="65" text-anchor="middle" fill="#ffffff" font-size="22" font-weight="bold" letter-spacing="1">ENTITY-RELATIONSHIP DIAGRAM (ERD): FORENSIC DATA REPOSITORY &amp; CUSTODY SCHEMA</text>
  <text x="880" y="88" text-anchor="middle" fill="#e0e7ff" font-size="13">Relational Entities, Primary &amp; Foreign Keys, Cardinalities (1:1, 1:N, N:M), and Cryptographic Evidence Vault Schemas</text>

  <!-- ENTITY 1: BRANDS (Top Left) -->
  <g transform="translate(60, 140)">
    <rect x="0" y="0" width="340" height="170" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.8" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="340" height="32" rx="8" fill="#082f49"/>
    <text x="170" y="22" text-anchor="middle" fill="#38bdf8" font-size="12" font-weight="bold">BRANDS</text>
    <text x="15" y="52" fill="#38bdf8" font-size="11" font-weight="bold">PK  brand_id : UUID</text>
    <text x="15" y="72" fill="#cbd5e1" font-size="11">    brand_name : VARCHAR(128)</text>
    <text x="15" y="92" fill="#cbd5e1" font-size="11">    official_domain : VARCHAR(255)</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    reference_logo_hash : CHAR(16)</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    monitored_since : TIMESTAMP</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    is_active : BOOLEAN</text>
  </g>

  <!-- ENTITY 2: SUSPICIOUS_DOMAINS (Center) -->
  <g transform="translate(480, 140)">
    <rect x="0" y="0" width="380" height="230" rx="8" fill="#1e293b" stroke="#f59e0b" stroke-width="2" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="380" height="32" rx="8" fill="#451a03"/>
    <text x="190" y="22" text-anchor="middle" fill="#f59e0b" font-size="12" font-weight="bold">SUSPICIOUS_DOMAINS</text>
    <text x="15" y="52" fill="#f59e0b" font-size="11" font-weight="bold">PK  domain_id : UUID</text>
    <text x="15" y="72" fill="#818cf8" font-size="11" font-weight="bold">FK  brand_id : UUID</text>
    <text x="15" y="92" fill="#cbd5e1" font-size="11">    domain_name : VARCHAR(255)</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    idn_punycode : VARCHAR(255)</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    tld : VARCHAR(32)</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    registrar_name : VARCHAR(128)</text>
    <text x="15" y="172" fill="#cbd5e1" font-size="11">    created_date : DATE</text>
    <text x="15" y="192" fill="#cbd5e1" font-size="11">    is_live : BOOLEAN</text>
    <text x="15" y="212" fill="#cbd5e1" font-size="11">    discovered_at : TIMESTAMP</text>
  </g>

  <!-- ENTITY 3: DNS_RECORDS (Top Right) -->
  <g transform="translate(940, 140)">
    <rect x="0" y="0" width="340" height="190" rx="8" fill="#1e293b" stroke="#0ea5e9" stroke-width="1.8" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="340" height="32" rx="8" fill="#082f49"/>
    <text x="170" y="22" text-anchor="middle" fill="#0ea5e9" font-size="12" font-weight="bold">DNS_RECORDS</text>
    <text x="15" y="52" fill="#0ea5e9" font-size="11" font-weight="bold">PK  record_id : UUID</text>
    <text x="15" y="72" fill="#f59e0b" font-size="11" font-weight="bold">FK  domain_id : UUID</text>
    <text x="15" y="92" fill="#cbd5e1" font-size="11">    record_type : ENUM(A, AAAA, MX, TXT, NS)</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    record_value : VARCHAR(512)</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    ttl : INTEGER</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    resolved_via : VARCHAR(64)</text>
    <text x="15" y="172" fill="#cbd5e1" font-size="11">    timestamp_utc : TIMESTAMP</text>
  </g>

  <!-- ENTITY 4: SSL_CERTIFICATES (Far Right) -->
  <g transform="translate(1360, 140)">
    <rect x="0" y="0" width="340" height="210" rx="8" fill="#1e293b" stroke="#0ea5e9" stroke-width="1.8" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="340" height="32" rx="8" fill="#082f49"/>
    <text x="170" y="22" text-anchor="middle" fill="#0ea5e9" font-size="12" font-weight="bold">SSL_CERTIFICATES</text>
    <text x="15" y="52" fill="#0ea5e9" font-size="11" font-weight="bold">PK  cert_id : UUID</text>
    <text x="15" y="72" fill="#f59e0b" font-size="11" font-weight="bold">FK  domain_id : UUID</text>
    <text x="15" y="92" fill="#cbd5e1" font-size="11">    issuer_cn : VARCHAR(255)</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    subject_cn : VARCHAR(255)</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    san_dns_names : TEXT</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    sha256_fingerprint : CHAR(64)</text>
    <text x="15" y="172" fill="#cbd5e1" font-size="11">    valid_from : TIMESTAMP</text>
    <text x="15" y="192" fill="#cbd5e1" font-size="11">    valid_to : TIMESTAMP</text>
  </g>

  <!-- ENTITY 5: VISUAL_ARTIFACTS (Middle Left) -->
  <g transform="translate(60, 440)">
    <rect x="0" y="0" width="340" height="210" rx="8" fill="#1e293b" stroke="#818cf8" stroke-width="1.8" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="340" height="32" rx="8" fill="#1e1b4b"/>
    <text x="170" y="22" text-anchor="middle" fill="#818cf8" font-size="12" font-weight="bold">VISUAL_ARTIFACTS</text>
    <text x="15" y="52" fill="#818cf8" font-size="11" font-weight="bold">PK  artifact_id : UUID</text>
    <text x="15" y="72" fill="#f59e0b" font-size="11" font-weight="bold">FK  domain_id : UUID</text>
    <text x="15" y="92" fill="#cbd5e1" font-size="11">    screenshot_vault_uri : VARCHAR(512)</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    phash_64_hex : CHAR(16)</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    dhash_64_hex : CHAR(16)</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    cielab_color_bins : BLOB</text>
    <text x="15" y="172" fill="#cbd5e1" font-size="11">    hamming_distance : INTEGER</text>
    <text x="15" y="192" fill="#cbd5e1" font-size="11">    similarity_pct : FLOAT</text>
  </g>

  <!-- ENTITY 6: NLP_CONTENT_ANALYSIS (Middle Center) -->
  <g transform="translate(480, 440)">
    <rect x="0" y="0" width="380" height="210" rx="8" fill="#1e293b" stroke="#818cf8" stroke-width="1.8" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="380" height="32" rx="8" fill="#1e1b4b"/>
    <text x="190" y="22" text-anchor="middle" fill="#818cf8" font-size="12" font-weight="bold">NLP_CONTENT_ANALYSIS</text>
    <text x="15" y="52" fill="#818cf8" font-size="11" font-weight="bold">PK  nlp_id : UUID</text>
    <text x="15" y="72" fill="#f59e0b" font-size="11" font-weight="bold">FK  domain_id : UUID</text>
    <text x="15" y="92" fill="#cbd5e1" font-size="11">    urgency_score : FLOAT</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    credential_harvest_flag : BOOLEAN</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    form_action_url : VARCHAR(512)</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    is_telegram_c2 : BOOLEAN</text>
    <text x="15" y="172" fill="#cbd5e1" font-size="11">    is_discord_c2 : BOOLEAN</text>
    <text x="15" y="192" fill="#cbd5e1" font-size="11">    zero_width_chars_count : INTEGER</text>
  </g>

  <!-- ENTITY 7: EMAIL_SECURITY_POSTURE (Middle Right) -->
  <g transform="translate(940, 440)">
    <rect x="0" y="0" width="340" height="210" rx="8" fill="#1e293b" stroke="#818cf8" stroke-width="1.8" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="340" height="32" rx="8" fill="#1e1b4b"/>
    <text x="170" y="22" text-anchor="middle" fill="#818cf8" font-size="12" font-weight="bold">EMAIL_SECURITY_POSTURE</text>
    <text x="15" y="52" fill="#818cf8" font-size="11" font-weight="bold">PK  email_sec_id : UUID</text>
    <text x="15" y="72" fill="#f59e0b" font-size="11" font-weight="bold">FK  domain_id : UUID</text>
    <text x="15" y="92" fill="#cbd5e1" font-size="11">    raw_spf_record : VARCHAR(512)</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    rfc7208_multi_spf_violation : BOOLEAN</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    raw_dmarc_record : VARCHAR(512)</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    dmarc_policy : ENUM(none, quarantine, reject)</text>
    <text x="15" y="172" fill="#cbd5e1" font-size="11">    dmarc_pct : INTEGER</text>
    <text x="15" y="192" fill="#cbd5e1" font-size="11">    bimi_vmc_valid : BOOLEAN</text>
  </g>

  <!-- ENTITY 8: INCIDENTS (Bottom Left) -->
  <g transform="translate(60, 750)">
    <rect x="0" y="0" width="340" height="230" rx="8" fill="#1e293b" stroke="#f43f5e" stroke-width="2" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="340" height="32" rx="8" fill="#4c0519"/>
    <text x="170" y="22" text-anchor="middle" fill="#f43f5e" font-size="12" font-weight="bold">INCIDENT_TRIAGE</text>
    <text x="15" y="52" fill="#f43f5e" font-size="11" font-weight="bold">PK  incident_id : VARCHAR(64)</text>
    <text x="15" y="72" fill="#38bdf8" font-size="11" font-weight="bold">FK  brand_id : UUID</text>
    <text x="15" y="92" fill="#f59e0b" font-size="11" font-weight="bold">FK  primary_domain_id : UUID</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    composite_risk_score : FLOAT</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    threat_tier : ENUM(CRIT, HIGH, MED, LOW, BEN)</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    synergy_multiplier : FLOAT</text>
    <text x="15" y="172" fill="#cbd5e1" font-size="11">    triage_status : VARCHAR(32)</text>
    <text x="15" y="192" fill="#cbd5e1" font-size="11">    assigned_analyst : VARCHAR(128)</text>
    <text x="15" y="212" fill="#cbd5e1" font-size="11">    created_at : TIMESTAMP</text>
  </g>

  <!-- ENTITY 9: EVIDENCE_BLOCKS (NIST SP 800-86) (Bottom Center) -->
  <g transform="translate(480, 750)">
    <rect x="0" y="0" width="440" height="250" rx="8" fill="#1e293b" stroke="#10b981" stroke-width="2" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="440" height="32" rx="8" fill="#064e3b"/>
    <text x="220" y="22" text-anchor="middle" fill="#10b981" font-size="12" font-weight="bold">EVIDENCE_CUSTODY_BLOCKS (NIST SP 800-86)</text>
    <text x="15" y="52" fill="#10b981" font-size="11" font-weight="bold">PK  block_id : UUID</text>
    <text x="15" y="72" fill="#10b981" font-size="11" font-weight="bold">    sequence_num : BIGINT (Sequential)</text>
    <text x="15" y="92" fill="#f59e0b" font-size="11" font-weight="bold">FK  domain_id : UUID</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    target_uri : VARCHAR(512)</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    artifact_sha256 : CHAR(64)</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    artifact_sha3_512 : CHAR(128)</text>
    <text x="15" y="172" fill="#cbd5e1" font-size="11">    previous_block_hash : CHAR(64)</text>
    <text x="15" y="192" fill="#cbd5e1" font-size="11">    block_hash : CHAR(64)</text>
    <text x="15" y="212" fill="#cbd5e1" font-size="11">    hmac_seal : CHAR(64)</text>
    <text x="15" y="232" fill="#cbd5e1" font-size="11">    timestamp_utc : TIMESTAMP</text>
  </g>

  <!-- ENTITY 10: TAKEDOWN_NOTICES (Bottom Right) -->
  <g transform="translate(1000, 750)">
    <rect x="0" y="0" width="360" height="210" rx="8" fill="#1e293b" stroke="#f43f5e" stroke-width="1.8" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="360" height="32" rx="8" fill="#4c0519"/>
    <text x="180" y="22" text-anchor="middle" fill="#f43f5e" font-size="12" font-weight="bold">TAKEDOWN_NOTICES</text>
    <text x="15" y="52" fill="#f43f5e" font-size="11" font-weight="bold">PK  notice_id : UUID</text>
    <text x="15" y="72" fill="#f43f5e" font-size="11" font-weight="bold">FK  incident_id : VARCHAR(64)</text>
    <text x="15" y="92" fill="#cbd5e1" font-size="11">    recipient_registrar_email : VARCHAR(255)</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    icann_raa_clause : VARCHAR(64)</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    embedded_evidence_hashes : TEXT</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    dispatch_status : ENUM(SENT, ACK, RESOLVED)</text>
    <text x="15" y="172" fill="#cbd5e1" font-size="11">    dispatched_at : TIMESTAMP</text>
    <text x="15" y="192" fill="#cbd5e1" font-size="11">    domain_suspended_at : TIMESTAMP</text>
  </g>

  <!-- ENTITY 11: THREAT_ACTORS (Far Bottom Right) -->
  <g transform="translate(1420, 750)">
    <rect x="0" y="0" width="300" height="190" rx="8" fill="#1e293b" stroke="#a855f7" stroke-width="1.8" filter="url(#shadow7)"/>
    <rect x="0" y="0" width="300" height="32" rx="8" fill="#3b0764"/>
    <text x="150" y="22" text-anchor="middle" fill="#a855f7" font-size="12" font-weight="bold">THREAT_ACTOR_ENTITIES</text>
    <text x="15" y="52" fill="#a855f7" font-size="11" font-weight="bold">PK  actor_id : UUID</text>
    <text x="15" y="72" fill="#cbd5e1" font-size="11">    syndicate_alias : VARCHAR(128)</text>
    <text x="15" y="92" fill="#cbd5e1" font-size="11">    associated_email : VARCHAR(255)</text>
    <text x="15" y="112" fill="#cbd5e1" font-size="11">    telegram_channel : VARCHAR(128)</text>
    <text x="15" y="132" fill="#cbd5e1" font-size="11">    primary_target_sector : VARCHAR(64)</text>
    <text x="15" y="152" fill="#cbd5e1" font-size="11">    confidence_score : FLOAT</text>
    <text x="15" y="172" fill="#cbd5e1" font-size="11">    first_observed : TIMESTAMP</text>
  </g>

  <!-- CARDINALITY RELATIONSHIP LINES (Crow's Foot Notation) -->
  <!-- BRANDS (1) -> (N) SUSPICIOUS_DOMAINS -->
  <line x1="400" y1="210" x2="480" y2="210" stroke="#38bdf8" stroke-width="2"/>
  <circle cx="410" cy="210" r="4" fill="#38bdf8"/>
  <line x1="420" y1="202" x2="420" y2="218" stroke="#38bdf8" stroke-width="2"/>
  <!-- Crow's foot at 480 -->
  <line x1="470" y1="202" x2="480" y2="210" stroke="#38bdf8" stroke-width="2"/>
  <line x1="470" y1="218" x2="480" y2="210" stroke="#38bdf8" stroke-width="2"/>
  <text x="440" y="200" text-anchor="middle" fill="#38bdf8" font-size="10">1 : N</text>

  <!-- SUSPICIOUS_DOMAINS (1) -> (N) DNS_RECORDS -->
  <line x1="860" y1="210" x2="940" y2="210" stroke="#0ea5e9" stroke-width="2"/>
  <text x="900" y="200" text-anchor="middle" fill="#0ea5e9" font-size="10">1 : N</text>

  <!-- SUSPICIOUS_DOMAINS (1) -> (1) SSL_CERTIFICATES -->
  <path d="M 860 170 L 1360 170" stroke="#0ea5e9" stroke-width="2"/>
  <text x="1110" y="160" text-anchor="middle" fill="#0ea5e9" font-size="10">1 : 1</text>

  <!-- SUSPICIOUS_DOMAINS (1) -> (1) VISUAL_ARTIFACTS -->
  <path d="M 580 370 L 580 400 L 230 400 L 230 440" stroke="#818cf8" stroke-width="2"/>
  <text x="380" y="390" text-anchor="middle" fill="#818cf8" font-size="10">1 : 1</text>

  <!-- SUSPICIOUS_DOMAINS (1) -> (1) NLP_CONTENT_ANALYSIS -->
  <line x1="670" y1="370" x2="670" y2="440" stroke="#818cf8" stroke-width="2"/>
  <text x="685" y="410" fill="#818cf8" font-size="10">1 : 1</text>

  <!-- SUSPICIOUS_DOMAINS (1) -> (1) EMAIL_SECURITY_POSTURE -->
  <path d="M 760 370 L 760 400 L 1110 400 L 1110 440" stroke="#818cf8" stroke-width="2"/>
  <text x="940" y="390" text-anchor="middle" fill="#818cf8" font-size="10">1 : 1</text>

  <!-- SUSPICIOUS_DOMAINS (1) -> (N) EVIDENCE_CUSTODY_BLOCKS -->
  <path d="M 700 650 L 700 750" stroke="#10b981" stroke-width="2.5"/>
  <text x="715" y="700" fill="#10b981" font-size="11" font-weight="bold">1 : N (Hash Chained)</text>

  <!-- INCIDENT_TRIAGE (1) -> (N) TAKEDOWN_NOTICES -->
  <line x1="400" y1="840" x2="1000" y2="840" stroke="#f43f5e" stroke-width="2"/>
  <text x="700" y="830" text-anchor="middle" fill="#f43f5e" font-size="10">1 : N (Takedown Actions)</text>

  <!-- ERD Legend & Notes -->
  <rect x="60" y="1070" width="1660" height="220" rx="8" fill="#1e293b" stroke="#334155"/>
  <text x="90" y="1100" fill="#e2e8f0" font-size="13" font-weight="bold">RELATIONAL SCHEMA SPECIFICATIONS &amp; FORENSIC INTEGRITY CONSTRAINTS:</text>
  <text x="90" y="1130" fill="#cbd5e1" font-size="11">1. Primary Keys (PK): Globally unique RFC 4122 UUID v4 identifiers, preventing collision across distributed forensic collectors.</text>
  <text x="90" y="1150" fill="#cbd5e1" font-size="11">2. Foreign Keys (FK): Referential integrity enforced with ON DELETE RESTRICT on evidence custody tables to prevent accidental evidentiary destruction.</text>
  <text x="90" y="1170" fill="#10b981" font-size="11" font-weight="bold">3. NIST SP 800-86 Invariant: EVIDENCE_CUSTODY_BLOCKS is an append-only table where block_hash = SHA256(previous_block_hash || domain_id || artifact_sha256 || timestamp_utc).</text>
  <text x="90" y="1190" fill="#cbd5e1" font-size="11">4. Dual-Digest Auditing: Parallel SHA-256 and SHA3-512 hashes guarantee quantum-resistant collision resistance for court admissibility.</text>
  <text x="90" y="1210" fill="#cbd5e1" font-size="11">5. Takedown Audit Trail: TAKEDOWN_NOTICES logs exact RFC 822 email transmission records and timestamped DNS suspension confirmations.</text>
</svg>"""

with open(OUT_DIR / "07_ENTITY_RELATIONSHIP_DIAGRAM.svg", "w", encoding="utf-8") as f:
    f.write(svg_7)

xml_7 = """
        <mxCell id="600" value="BRANDS&#xa;PK brand_id : UUID&#xa;brand_name : VARCHAR(128)&#xa;official_domain : VARCHAR(255)&#xa;reference_logo_hash : CHAR(16)&#xa;monitored_since : TIMESTAMP" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#38bdf8;fontColor=#ffffff;align=left;spacingLeft=10;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="80" y="160" width="280" height="150" as="geometry"/>
        </mxCell>
        <mxCell id="601" value="SUSPICIOUS_DOMAINS&#xa;PK domain_id : UUID&#xa;FK brand_id : UUID&#xa;domain_name : VARCHAR(255)&#xa;idn_punycode : VARCHAR(255)&#xa;tld : VARCHAR(32)&#xa;registrar_name : VARCHAR(128)&#xa;is_live : BOOLEAN" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#f59e0b;fontColor=#ffffff;align=left;spacingLeft=10;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="440" y="160" width="300" height="180" as="geometry"/>
        </mxCell>
        <mxCell id="602" value="DNS_RECORDS&#xa;PK record_id : UUID&#xa;FK domain_id : UUID&#xa;record_type : VARCHAR(16)&#xa;record_value : VARCHAR(512)&#xa;ttl : INTEGER" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#0ea5e9;fontColor=#ffffff;align=left;spacingLeft=10;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="820" y="160" width="260" height="150" as="geometry"/>
        </mxCell>
        <mxCell id="603" value="VISUAL_ARTIFACTS&#xa;PK artifact_id : UUID&#xa;FK domain_id : UUID&#xa;screenshot_vault_uri : VARCHAR(512)&#xa;phash_64_hex : CHAR(16)&#xa;similarity_pct : FLOAT" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#818cf8;fontColor=#ffffff;align=left;spacingLeft=10;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="80" y="420" width="280" height="150" as="geometry"/>
        </mxCell>
        <mxCell id="604" value="EVIDENCE_CUSTODY_BLOCKS (NIST)&#xa;PK block_id : UUID&#xa;sequence_num : BIGINT&#xa;FK domain_id : UUID&#xa;artifact_sha256 : CHAR(64)&#xa;previous_block_hash : CHAR(64)&#xa;block_hash : CHAR(64)&#xa;hmac_seal : CHAR(64)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#10b981;fontColor=#ffffff;align=left;spacingLeft=10;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="440" y="420" width="340" height="180" as="geometry"/>
        </mxCell>
        <mxCell id="605" value="INCIDENT_TRIAGE&#xa;PK incident_id : VARCHAR(64)&#xa;FK brand_id : UUID&#xa;FK primary_domain_id : UUID&#xa;composite_risk_score : FLOAT&#xa;threat_tier : VARCHAR(32)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#f43f5e;fontColor=#ffffff;align=left;spacingLeft=10;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="860" y="420" width="280" height="150" as="geometry"/>
        </mxCell>

        <mxCell id="610" value="1 : N" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#38bdf8;fontColor=#38bdf8;" edge="1" parent="1" source="600" target="601"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="611" value="1 : N" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#0ea5e9;fontColor=#0ea5e9;" edge="1" parent="1" source="601" target="602"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="612" value="1 : 1" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#818cf8;fontColor=#818cf8;" edge="1" parent="1" source="601" target="603"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="613" value="1 : N (Custody)" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#10b981;fontColor=#10b981;strokeWidth=2;" edge="1" parent="1" source="601" target="604"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="614" value="1 : 1" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#f43f5e;fontColor=#f43f5e;" edge="1" parent="1" source="601" target="605"><mxGeometry relative="1" as="geometry"/></mxCell>
"""
with open(OUT_DIR / "07_ENTITY_RELATIONSHIP_DIAGRAM.drawio", "w", encoding="utf-8") as f:
    f.write(wrap_drawio("diag_erd", "Entity-Relationship Diagram", xml_7, 1760, 1350))

print("Diagram 7 completed.")

print("Preparing Diagram 8: Graph-Based Link Analysis & Network Topology Diagram...")
# -------------------------------------------------------------
# 8. GRAPH LINK ANALYSIS DIAGRAM
# -------------------------------------------------------------
svg_8 = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1760 1350" width="100%" height="100%" style="background:#090d16; font-family:'Segoe UI', Inter, -apple-system, sans-serif;">
  <defs>
    <linearGradient id="bgHeader8" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#4f46e5"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
    <filter id="shadow8" x="-5%" y="-5%" width="110%" height="110%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.5"/>
    </filter>
    <marker id="linkArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#94a3b8"/>
    </marker>
    <marker id="threatArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e"/>
    </marker>
    <marker id="c2Arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#ec4899"/>
    </marker>
  </defs>

  <!-- Title Banner -->
  <rect x="40" y="30" width="1680" height="70" rx="10" fill="url(#bgHeader8)" filter="url(#shadow8)"/>
  <text x="880" y="65" text-anchor="middle" fill="#ffffff" font-size="22" font-weight="bold" letter-spacing="1">GRAPH LINK ANALYSIS &amp; INFRASTRUCTURE TOPOLOGY: THREAT SYNDICATE CORRELATION</text>
  <text x="880" y="88" text-anchor="middle" fill="#e0e7ff" font-size="13">Heterogeneous Entity Network, Degree &amp; Betweenness Centrality, Shared Bulletproof Infrastructure, and C2 Exfiltration Pathways</text>

  <!-- Network Canvas Container -->
  <rect x="50" y="130" width="1660" height="980" rx="14" fill="#0b1120" stroke="#1e293b" stroke-width="2" filter="url(#shadow8)"/>

  <!-- CENTRAL BRAND TARGET NODE (Target: PayPal) -->
  <g transform="translate(800, 620)">
    <circle cx="0" cy="0" r="65" fill="#064e3b" stroke="#10b981" stroke-width="3" filter="url(#shadow8)"/>
    <text x="0" y="-8" text-anchor="middle" fill="#ffffff" font-size="14" font-weight="bold">TARGET BRAND</text>
    <text x="0" y="12" text-anchor="middle" fill="#34d399" font-size="16" font-weight="bold">PayPal, Inc.</text>
    <text x="0" y="30" text-anchor="middle" fill="#a7f3d0" font-size="10">paypal.com (Official)</text>
  </g>

  <!-- THREAT ACTOR SYNDICATE NODE (Top Center) -->
  <g transform="translate(800, 220)">
    <polygon points="0,-45 40,-25 40,25 0,45 -40,25 -40,-25" fill="#4c0519" stroke="#f43f5e" stroke-width="3" filter="url(#shadow8)"/>
    <text x="0" y="-8" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">THREAT ACTOR</text>
    <text x="0" y="10" text-anchor="middle" fill="#fda4af" font-size="13" font-weight="bold">APT-PhishGroup-88</text>
    <text x="0" y="26" text-anchor="middle" fill="#94a3b8" font-size="9">Syndicate Cluster #14</text>
  </g>

  <!-- ACTOR REGISTRANT EMAIL -->
  <g transform="translate(1120, 220)">
    <ellipse cx="0" cy="0" rx="120" ry="35" fill="#1e293b" stroke="#f59e0b" stroke-width="2" filter="url(#shadow8)"/>
    <text x="0" y="-3" text-anchor="middle" fill="#f59e0b" font-size="11" font-weight="bold">Registrant Identity</text>
    <text x="0" y="15" text-anchor="middle" fill="#ffffff" font-size="10">privacy-guard@scam-protect[.]ru</text>
  </g>

  <!-- IMPERSONATING LOOKALIKE DOMAIN NODES -->
  <!-- Domain 1 (Top Left of Target) -->
  <g transform="translate(420, 480)">
    <rect x="-130" y="-35" width="260" height="70" rx="10" fill="#1e293b" stroke="#f43f5e" stroke-width="2.5" filter="url(#shadow8)"/>
    <text x="0" y="-12" text-anchor="middle" fill="#f43f5e" font-size="11" font-weight="bold">[LOOKALIKE DOMAIN 1]</text>
    <text x="0" y="8" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">paypa1-security-update.com</text>
    <text x="0" y="24" text-anchor="middle" fill="#fda4af" font-size="10">Risk: 96/100 (CRITICAL)</text>
  </g>

  <!-- Domain 2 (Bottom Left of Target) -->
  <g transform="translate(420, 760)">
    <rect x="-130" y="-35" width="260" height="70" rx="10" fill="#1e293b" stroke="#f43f5e" stroke-width="2.5" filter="url(#shadow8)"/>
    <text x="0" y="-12" text-anchor="middle" fill="#f43f5e" font-size="11" font-weight="bold">[LOOKALIKE DOMAIN 2]</text>
    <text x="0" y="8" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">paypal-verify-account.top</text>
    <text x="0" y="24" text-anchor="middle" fill="#fda4af" font-size="10">Risk: 92/100 (CRITICAL)</text>
  </g>

  <!-- Domain 3 (Right of Target) -->
  <g transform="translate(1220, 620)">
    <rect x="-130" y="-35" width="260" height="70" rx="10" fill="#1e293b" stroke="#f59e0b" stroke-width="2" filter="url(#shadow8)"/>
    <text x="0" y="-12" text-anchor="middle" fill="#f59e0b" font-size="11" font-weight="bold">[COMBOSQUAT DOMAIN 3]</text>
    <text x="0" y="8" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="bold">secure-paypal-login.xyz</text>
    <text x="0" y="24" text-anchor="middle" fill="#fde68a" font-size="10">Risk: 84/100 (HIGH)</text>
  </g>

  <!-- SHARED INFRASTRUCTURE NODES -->
  <!-- Shared Bulletproof IP 1 -->
  <g transform="translate(180, 620)">
    <ellipse cx="0" cy="0" rx="110" ry="40" fill="#1e293b" stroke="#a855f7" stroke-width="2.5" filter="url(#shadow8)"/>
    <text x="0" y="-8" text-anchor="middle" fill="#a855f7" font-size="11" font-weight="bold">SHARED FAST-FLUX IP</text>
    <text x="0" y="10" text-anchor="middle" fill="#ffffff" font-size="13" font-weight="bold">185.220.101.5</text>
    <text x="0" y="26" text-anchor="middle" fill="#c084fc" font-size="9">Degree Centrality: 5 (Pivot)</text>
  </g>

  <!-- Shared Bulletproof ASN -->
  <g transform="translate(180, 880)">
    <polygon points="0,-40 70,0 0,40 -70,0" fill="#1e293b" stroke="#f59e0b" stroke-width="2" filter="url(#shadow8)"/>
    <text x="0" y="-5" text-anchor="middle" fill="#f59e0b" font-size="10" font-weight="bold">BULLETPROOF ASN</text>
    <text x="0" y="12" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">AS44477</text>
    <text x="0" y="24" text-anchor="middle" fill="#94a3b8" font-size="8">Stark LLC (Seychelles)</text>
  </g>

  <!-- Shared Nameserver (Betweenness Centrality Hub) -->
  <g transform="translate(800, 420)">
    <polygon points="0,-35 45,-15 45,20 0,40 -45,20 -45,-15" fill="#1e293b" stroke="#14b8a6" stroke-width="2" filter="url(#shadow8)"/>
    <text x="0" y="-6" text-anchor="middle" fill="#14b8a6" font-size="10" font-weight="bold">NAMESERVER HUB</text>
    <text x="0" y="10" text-anchor="middle" fill="#ffffff" font-size="10" font-weight="bold">ns1.bulletproof-dns.org</text>
    <text x="0" y="24" text-anchor="middle" fill="#5eead4" font-size="8">Betweenness: 0.84</text>
  </g>

  <!-- CLONED VISUAL ASSET NODE -->
  <g transform="translate(580, 940)">
    <rect x="-100" y="-30" width="200" height="60" rx="8" fill="#1e1b4b" stroke="#6366f1" stroke-width="2" filter="url(#shadow8)"/>
    <text x="0" y="-8" text-anchor="middle" fill="#818cf8" font-size="10" font-weight="bold">CLONED LOGO ASSET</text>
    <text x="0" y="8" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">paypal_emblem.png</text>
    <text x="0" y="22" text-anchor="middle" fill="#a5b4fc" font-size="9">pHash: 0x8f3c4e... (Dist: 2)</text>
  </g>

  <!-- CREDENTIAL EXFILTRATION C2 WEBHOOK -->
  <g transform="translate(1220, 880)">
    <polygon points="0,-35 45,35 -45,35" fill="#4c0519" stroke="#ec4899" stroke-width="2" filter="url(#shadow8)"/>
    <text x="0" y="-3" text-anchor="middle" fill="#ec4899" font-size="10" font-weight="bold">C2 EXFILTRATION</text>
    <text x="0" y="14" text-anchor="middle" fill="#ffffff" font-size="9" font-weight="bold">Telegram Bot API</text>
    <text x="0" y="26" text-anchor="middle" fill="#f472b6" font-size="8">bot&lt;token&gt;/sendMessage</text>
  </g>

  <!-- SOCIAL IMPERSONATION HANDLE -->
  <g transform="translate(1220, 380)">
    <circle cx="0" cy="0" r="45" fill="#1e293b" stroke="#38bdf8" stroke-width="2" filter="url(#shadow8)"/>
    <text x="0" y="-10" text-anchor="middle" fill="#38bdf8" font-size="9" font-weight="bold">TWITTER SPOOF</text>
    <text x="0" y="6" text-anchor="middle" fill="#ffffff" font-size="9" font-weight="bold">@PayPaI_Care</text>
    <text x="0" y="20" text-anchor="middle" fill="#f59e0b" font-size="8">Emoji Badge ✔️</text>
  </g>

  <!-- GRAPH EDGES (Correlations & Link Analysis) -->
  <!-- Domains TARGET PayPal -->
  <line x1="550" y1="510" x2="740" y2="585" stroke="#f43f5e" stroke-width="2.5" marker-end="url(#threatArrow)"/>
  <text x="640" y="535" fill="#f43f5e" font-size="10" font-weight="bold">TARGETS</text>

  <line x1="550" y1="740" x2="740" y2="655" stroke="#f43f5e" stroke-width="2.5" marker-end="url(#threatArrow)"/>
  <text x="640" y="710" fill="#f43f5e" font-size="10" font-weight="bold">TARGETS</text>

  <line x1="1090" y1="620" x2="865" y2="620" stroke="#f59e0b" stroke-width="2" marker-end="url(#threatArrow)"/>
  <text x="980" y="610" text-anchor="middle" fill="#f59e0b" font-size="10" font-weight="bold">TARGETS</text>

  <!-- Domains RESOLVE_TO Shared IP 185.220.101.5 -->
  <line x1="290" y1="495" x2="220" y2="580" stroke="#a855f7" stroke-width="2" marker-end="url(#linkArrow)"/>
  <text x="235" y="525" fill="#a855f7" font-size="9">RESOLVES_TO</text>

  <line x1="290" y1="745" x2="220" y2="660" stroke="#a855f7" stroke-width="2" marker-end="url(#linkArrow)"/>
  <text x="235" y="715" fill="#a855f7" font-size="9">RESOLVES_TO</text>

  <!-- IP 1 LOCATED_IN ASN44477 -->
  <line x1="180" y1="660" x2="180" y2="840" stroke="#f59e0b" stroke-width="2" stroke-dasharray="4,4" marker-end="url(#linkArrow)"/>
  <text x="190" y="750" fill="#f59e0b" font-size="9">HOSTED_ON</text>

  <!-- Domains DELEGATED_TO ns1.bulletproof-dns.org -->
  <line x1="550" y1="470" x2="755" y2="430" stroke="#14b8a6" stroke-width="1.8" marker-end="url(#linkArrow)"/>
  <text x="660" y="440" fill="#14b8a6" font-size="9">USES_NAMESERVER</text>

  <line x1="1090" y1="600" x2="845" y2="445" stroke="#14b8a6" stroke-width="1.8" marker-end="url(#linkArrow)"/>

  <!-- Actor CONTROLS Nameserver & Domains -->
  <line x1="800" y1="265" x2="800" y2="385" stroke="#f43f5e" stroke-width="2" stroke-dasharray="5,4" marker-end="url(#threatArrow)"/>
  <text x="810" y="325" fill="#f43f5e" font-size="9">CONTROLS</text>

  <line x1="840" y1="220" x2="1000" y2="220" stroke="#f59e0b" stroke-width="1.8" marker-end="url(#linkArrow)"/>
  <text x="920" y="210" text-anchor="middle" fill="#f59e0b" font-size="9">USES_EMAIL</text>

  <!-- Domains CLONES Logo Asset -->
  <line x1="450" y1="795" x2="540" y2="910" stroke="#818cf8" stroke-width="1.8" marker-end="url(#linkArrow)"/>
  <text x="470" y="860" fill="#818cf8" font-size="9">EXPLOITS_LOGO</text>

  <!-- Domain 3 EXFILTRATES to Telegram C2 -->
  <line x1="1220" y1="655" x2="1220" y2="845" stroke="#ec4899" stroke-width="2.5" marker-end="url(#c2Arrow)"/>
  <text x="1230" y="750" fill="#ec4899" font-size="10" font-weight="bold">EXFILTRATES_TO_C2</text>

  <!-- Actor OPERATES Twitter Spoof -->
  <line x1="840" y1="240" x2="1175" y2="380" stroke="#38bdf8" stroke-width="1.8" stroke-dasharray="4,4" marker-end="url(#linkArrow)"/>
  <text x="1000" y="300" fill="#38bdf8" font-size="9">OPERATES_HANDLE</text>

  <!-- GRAPH ANALYTICS METRICS SUMMARY BOX -->
  <rect x="70" y="1130" width="1620" height="150" rx="8" fill="#1e293b" stroke="#334155"/>
  <text x="95" y="1158" fill="#e2e8f0" font-size="13" font-weight="bold">GRAPH TOPOLOGY &amp; LINK ANALYSIS INSIGHTS FOR ADVERSARY SYNDICATE ISOLATION:</text>
  <text x="95" y="1185" fill="#cbd5e1" font-size="11">1. High-Fanout Infrastructure Pivot: IP 185.220.101.5 hosts 2 active lookalikes simultaneously with degree centrality = 5, establishing a single infrastructure hosting provider footprint.</text>
  <text x="95" y="1205" fill="#cbd5e1" font-size="11">2. Bottleneck Articulation Point: ns1.bulletproof-dns.org possesses betweenness centrality = 0.84, revealing that taking down this single authoritative nameserver dismantles the adversary's routing topology across all 3 attack domains.</text>
  <text x="95" y="1225" fill="#fda4af" font-size="11">3. Non-Linear Synergy Bonus: Simultaneous presence of homoglyph domain + cloned visual logo (pHash dist &lt;= 3) + active Telegram C2 trigger triggers the full +20 pt synergy bonus, yielding 96/100 CRITICAL risk.</text>
  <text x="95" y="1245" fill="#a7f3d0" font-size="11">4. Actionable Remediation: The graph automatically targets ICANN registrar takedown against domain registrars while issuing an upstream cease-and-desist to AS44477 (Hosting ISP).</text>
</svg>"""

with open(OUT_DIR / "08_GRAPH_LINK_ANALYSIS_DIAGRAM.svg", "w", encoding="utf-8") as f:
    f.write(svg_8)

xml_8 = """
        <mxCell id="700" value="TARGET BRAND&#xa;PayPal, Inc.&#xa;(paypal.com)" style="ellipse;whiteSpace=wrap;html=1;fillColor=#064e3b;strokeColor=#10b981;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="720" y="560" width="160" height="120" as="geometry"/>
        </mxCell>
        <mxCell id="701" value="THREAT ACTOR&#xa;APT-PhishGroup-88" style="shape=hexagon;perimeter=hexagonPerimeter2;whiteSpace=wrap;html=1;fillColor=#4c0519;strokeColor=#f43f5e;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="720" y="180" width="160" height="80" as="geometry"/>
        </mxCell>
        <mxCell id="702" value="LOOKALIKE DOMAIN 1&#xa;paypa1-security-update.com&#xa;Risk: 96 (CRITICAL)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#f43f5e;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="320" y="440" width="220" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="703" value="LOOKALIKE DOMAIN 2&#xa;paypal-verify-account.top&#xa;Risk: 92 (CRITICAL)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#f43f5e;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="320" y="720" width="220" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="704" value="COMBOSQUAT DOMAIN 3&#xa;secure-paypal-login.xyz&#xa;Risk: 84 (HIGH)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#f59e0b;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="1120" y="580" width="220" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="705" value="SHARED BULLETPROOF IP&#xa;185.220.101.5&#xa;(Degree: 5)" style="ellipse;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#a855f7;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="80" y="580" width="180" height="80" as="geometry"/>
        </mxCell>
        <mxCell id="706" value="NAMESERVER HUB&#xa;ns1.bulletproof-dns.org&#xa;(Betweenness: 0.84)" style="shape=hexagon;perimeter=hexagonPerimeter2;whiteSpace=wrap;html=1;fillColor=#1e293b;strokeColor=#14b8a6;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="700" y="380" width="200" height="70" as="geometry"/>
        </mxCell>
        <mxCell id="707" value="C2 EXFILTRATION&#xa;Telegram Bot Webhook" style="triangle;whiteSpace=wrap;html=1;fillColor=#4c0519;strokeColor=#ec4899;fontColor=#ffffff;fontStyle=1;" vertex="1" parent="1">
          <mxGeometry x="1140" y="820" width="180" height="90" as="geometry"/>
        </mxCell>

        <mxCell id="710" value="TARGETS" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#f43f5e;fontColor=#f43f5e;strokeWidth=2;" edge="1" parent="1" source="702" target="700"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="711" value="TARGETS" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#f43f5e;fontColor=#f43f5e;strokeWidth=2;" edge="1" parent="1" source="703" target="700"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="712" value="TARGETS" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#f59e0b;fontColor=#f59e0b;strokeWidth=2;" edge="1" parent="1" source="704" target="700"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="713" value="RESOLVES_TO" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#a855f7;fontColor=#a855f7;" edge="1" parent="1" source="702" target="705"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="714" value="RESOLVES_TO" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#a855f7;fontColor=#a855f7;" edge="1" parent="1" source="703" target="705"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="715" value="USES_NAMESERVER" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#14b8a6;fontColor=#14b8a6;" edge="1" parent="1" source="702" target="706"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="716" value="CONTROLS" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#f43f5e;fontColor=#f43f5e;dashed=1;" edge="1" parent="1" source="701" target="706"><mxGeometry relative="1" as="geometry"/></mxCell>
        <mxCell id="717" value="EXFILTRATES_TO_C2" style="edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#ec4899;fontColor=#ec4899;strokeWidth=2;" edge="1" parent="1" source="704" target="707"><mxGeometry relative="1" as="geometry"/></mxCell>
"""
with open(OUT_DIR / "08_GRAPH_LINK_ANALYSIS_DIAGRAM.drawio", "w", encoding="utf-8") as f:
    f.write(wrap_drawio("diag_graph", "Graph Link Analysis Diagram", xml_8, 1760, 1350))

print("Diagram 8 completed.")
print("All 8 Diagrams generated successfully in Design/design/!")
