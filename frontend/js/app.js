/**
 * AegisOSINT - Frontend Application Controller
 * Handles workbench state, multimodal scanning APIs, case dossiers, and takedown generation.
 */

let allCases = [];
let currentCase = null;
let currentDossier = null;
let currentSTIX = null;

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(el => {
    el.classList.remove('active', 'text-indigo-400', 'bg-indigo-500/10');
    el.classList.add('text-slate-400');
  });

  const activeContent = document.getElementById(`tab-content-${tabId}`);
  const activeBtn = document.getElementById(`tab-btn-${tabId}`);

  if (activeContent) activeContent.classList.remove('hidden');
  if (activeBtn) {
    activeBtn.classList.add('active', 'text-indigo-400', 'bg-indigo-500/10');
    activeBtn.classList.remove('text-slate-400');
  }

  // Hook tab-specific initializers
  if (tabId === 'graph') {
    setTimeout(refreshThreatGraph, 100);
  } else if (tabId === 'evidence') {
    loadEvidenceLedger();
  } else if (tabId === 'osint') {
    runXAIExplain();
  }
}

// Initialize Application on Page Load
document.addEventListener('DOMContentLoaded', async () => {
  await fetchCases();
  await refreshThreatGraph();
  await loadEvidenceLedger();
  runXAIExplain();
});

// REAL-WORLD LIVE TARGET INTELLIGENCE SCANNER (100% Real Internet Recon)
async function executeRealLiveScan() {
  const targetInput = document.getElementById('live-target-input');
  const brandInput = document.getElementById('live-brand-input');
  const scanBtn = document.getElementById('btn-live-scan');
  const resultsBox = document.getElementById('live-scan-results-box');

  const target = targetInput ? targetInput.value.trim() : '';
  const brand = brandInput ? brandInput.value.trim() : 'PayPal';

  if (!target) {
    alert("Please enter a domain or URL to scan (e.g., github.com or paypal.com)");
    return;
  }

  // Update button to loading state
  const origBtnHtml = scanBtn.innerHTML;
  scanBtn.disabled = true;
  scanBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Probing Live Net...`;

  try {
    const res = await fetch('/api/scan/live-deep', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, brand })
    });

    if (!res.ok) {
      throw new Error(`HTTP error ${res.status}`);
    }

    const data = await res.json();

    // Reveal results box
    if (resultsBox) resultsBox.classList.remove('hidden');

    // Header info
    const domEl = document.getElementById('live-result-domain');
    if (domEl) domEl.innerText = data.target;

    const sevEl = document.getElementById('live-result-severity');
    if (sevEl) {
      const isCritical = data.risk.severity === 'CRITICAL';
      const isHigh = data.risk.severity === 'HIGH';
      const isSuspicious = data.risk.severity === 'SUSPICIOUS';
      const badgeClass = isCritical
        ? 'bg-red-500/20 text-red-300 border-red-500/40'
        : isHigh
        ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
        : isSuspicious
        ? 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40'
        : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      sevEl.className = `px-2.5 py-0.5 rounded text-xs font-bold border ${badgeClass}`;
      sevEl.innerText = `${data.risk.severity} (${data.risk.risk_score}/100)`;
    }

    // Card 1: DNS
    const dnsIps = document.getElementById('live-dns-ips');
    if (dnsIps) {
      dnsIps.innerText = data.dns.resolved && data.dns.ip_addresses && data.dns.ip_addresses.length > 0
        ? data.dns.ip_addresses.join(', ')
        : 'Unresolved / No A Records';
    }
    const dnsMx = document.getElementById('live-dns-mx');
    if (dnsMx) {
      dnsMx.innerText = data.dns.mx_records && data.dns.mx_records.length > 0
        ? data.dns.mx_records.slice(0, 2).join(', ')
        : 'No MX Records';
    }
    const dnsNs = document.getElementById('live-dns-ns');
    if (dnsNs) {
      dnsNs.innerText = data.dns.name_servers && data.dns.name_servers.length > 0
        ? data.dns.name_servers.slice(0, 2).join(', ')
        : 'Unknown NS';
    }

    // Card 2: RDAP
    const rdapReg = document.getElementById('live-rdap-registrar');
    if (rdapReg) rdapReg.innerText = data.rdap.registrar || 'Redacted / ICANN Protected';

    const rdapCreated = document.getElementById('live-rdap-created');
    if (rdapCreated) {
      rdapCreated.innerText = data.rdap.creation_date
        ? data.rdap.creation_date.replace('T', ' ').substring(0, 19)
        : 'Not Disclosed';
    }

    const rdapAge = document.getElementById('live-rdap-age');
    if (rdapAge) {
      rdapAge.innerText = (data.rdap.domain_age_days !== null && data.rdap.domain_age_days !== undefined)
        ? `${data.rdap.domain_age_days} days`
        : 'Unknown';
    }

    // Card 3: SSL
    const sslIssuer = document.getElementById('live-ssl-issuer');
    if (sslIssuer) {
      sslIssuer.innerText = data.ssl.has_ssl
        ? (data.ssl.issuer || 'Valid SSL')
        : 'No Active SSL Certificate';
    }
    const sslSubj = document.getElementById('live-ssl-subject');
    if (sslSubj) {
      sslSubj.innerText = data.ssl.has_ssl
        ? (data.ssl.subject || data.target)
        : 'N/A';
    }
    const sslFp = document.getElementById('live-ssl-fp');
    if (sslFp) {
      sslFp.innerText = data.ssl.sha256_fingerprint || 'N/A';
      sslFp.title = data.ssl.sha256_fingerprint || '';
    }

    // Card 4: HTTP
    const httpStat = document.getElementById('live-http-status');
    if (httpStat) {
      httpStat.innerText = data.http.reachable
        ? `HTTP ${data.http.status_code}`
        : 'Unreachable';
      httpStat.className = data.http.reachable
        ? 'font-mono font-bold text-emerald-400'
        : 'font-mono font-bold text-red-400';
    }
    const httpServer = document.getElementById('live-http-server');
    if (httpServer) {
      httpServer.innerText = data.http.server ? `(${data.http.server})` : '';
    }
    const httpTitle = document.getElementById('live-http-title');
    if (httpTitle) {
      httpTitle.innerText = data.http.title || 'No Title Found';
      httpTitle.title = data.http.title || '';
    }
    const httpSec = document.getElementById('live-http-security');
    if (httpSec) {
      httpSec.innerText = data.http.has_login_form
        ? '⚠️ Credential Form Detected'
        : 'Standard Web Application';
    }

    // Card 5: CT Logs & Wayback
    const ctCount = document.getElementById('live-ct-count');
    if (ctCount) {
      const ctFound = data.certificate_transparency
        ? (data.certificate_transparency.total_certificates_found || 0)
        : 0;
      ctCount.innerText = `${ctFound} subdomains discovered`;
    }
    const wbFirst = document.getElementById('live-wb-first');
    if (wbFirst) {
      wbFirst.innerText = data.wayback_archive && data.wayback_archive.first_snapshot_timestamp
        ? data.wayback_archive.first_snapshot_timestamp.substring(0, 8)
        : 'Never Archived';
    }
    const wbVerdict = document.getElementById('live-wb-verdict');
    if (wbVerdict) {
      wbVerdict.innerText = data.wayback_archive
        ? (data.wayback_archive.threat_verdict || 'Active')
        : 'Live';
    }

    // Card 6: Evidence
    const evId = document.getElementById('live-ev-id');
    if (evId && data.evidence_receipt) {
      evId.innerText = data.evidence_receipt.evidence_id;
    }
    const evHash = document.getElementById('live-ev-hash');
    if (evHash && data.evidence_receipt) {
      evHash.innerText = data.evidence_receipt.sha256_hash || data.evidence_receipt.sha256_digest || '';
      evHash.title = data.evidence_receipt.sha256_hash || '';
    }
    const evTs = document.getElementById('live-ev-ts');
    if (evTs && data.evidence_receipt) {
      evTs.innerText = (data.evidence_receipt.timestamp_utc || '').replace('T', ' ').substring(0, 19);
    }

    // Refresh graph and evidence tables with newly ingested real data
    await refreshThreatGraph();
    await loadEvidenceLedger();

  } catch (err) {
    alert("Live Reconnaissance Error: " + err.message);
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = origBtnHtml;
  }
}

function quickRealScan(domain, brand) {
  const targetInput = document.getElementById('live-target-input');
  const brandInput = document.getElementById('live-brand-input');
  if (targetInput) targetInput.value = domain;
  if (brandInput) brandInput.value = brand;
  executeRealLiveScan();
}

// 1. Fetch & Render Cases
async function fetchCases() {
  try {
    const res = await fetch('/api/cases');
    allCases = await res.json();
    renderCaseCards(allCases);
    if (allCases.length > 0) {
      selectCase(allCases[0].case_id);
    }
  } catch (err) {
    console.error("Failed to fetch cases:", err);
  }
}

function renderCaseCards(cases) {
  const container = document.getElementById('cases-cards-container');
  if (!container) return;
  container.innerHTML = '';

  cases.forEach(c => {
    const isCritical = c.precalculated_risk.severity === 'CRITICAL';
    const card = document.createElement('div');
    card.className = `p-4 rounded-xl border transition cursor-pointer ${
      currentCase && currentCase.case_id === c.case_id
        ? 'bg-slate-800/90 border-indigo-500 shadow-md shadow-indigo-500/20'
        : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
    }`;
    card.onclick = () => selectCase(c.case_id);

    card.innerHTML = `
      <div class="flex items-center justify-between mb-2">
        <span class="text-[10px] font-mono px-2 py-0.5 rounded ${isCritical ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'} font-bold">
          ${c.case_id}
        </span>
        <span class="text-xs font-mono font-bold ${isCritical ? 'text-red-400' : 'text-amber-400'}">
          ${c.precalculated_risk.risk_score} / 100
        </span>
      </div>
      <h3 class="text-xs font-bold text-white mb-1 line-clamp-1">${c.case_title}</h3>
      <p class="text-[11px] text-slate-400 line-clamp-1">Brand: <span class="text-slate-200">${c.target_brand}</span></p>
      <div class="mt-3 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-500">
        <span class="font-mono">${c.primary_threat_domain}</span>
        <span class="text-indigo-400 font-semibold">Inspect &rarr;</span>
      </div>
    `;
    container.appendChild(card);
  });
}

function selectCase(caseId) {
  const found = allCases.find(c => c.case_id === caseId);
  if (!found) return;
  currentCase = found;
  renderCaseCards(allCases); // Re-render to highlight active card

  // Update Case View elements
  document.getElementById('case-badge-id').innerText = found.case_id;
  document.getElementById('case-badge-severity').innerText = `${found.precalculated_risk.severity} (${found.precalculated_risk.risk_score}/100)`;
  document.getElementById('case-badge-severity').className = `px-2.5 py-0.5 rounded text-xs font-semibold ${
    found.precalculated_risk.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border border-red-500/40' : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
  }`;
  document.getElementById('case-view-title').innerText = found.case_title;
  document.getElementById('case-view-brand').innerHTML = `Targeting: <strong class="text-slate-200">${found.target_brand}</strong> (Official: ${found.authentic_domain} / ${found.authentic_handle})`;

  document.getElementById('case-primary-domain').innerText = found.primary_threat_domain;
  document.getElementById('case-assoc-domains').innerText = found.associated_domains.join(', ');
  document.getElementById('case-ip-asn').innerText = `${found.infrastructure.ip_addresses.join(', ')} (${found.infrastructure.asn})`;
  document.getElementById('case-reg-ssl').innerText = `${found.infrastructure.registrar} / ${found.infrastructure.ssl_issuer}`;

  if (found.social_impersonation) {
    document.getElementById('case-social-handle').innerText = `${found.social_impersonation.handle} (${found.social_impersonation.platform})`;
    document.getElementById('case-social-name').innerText = `${found.social_impersonation.display_name}`;
  }

  if (found.communication_lure) {
    document.getElementById('case-lure-sample').innerText = `"${found.communication_lure.message_text}"`;
  }

  // Multi-factor breakdown bars
  const p = found.precalculated_risk;
  const barsContainer = document.getElementById('case-risk-breakdown-bars');
  barsContainer.innerHTML = `
    <div>
      <div class="flex justify-between text-[11px] mb-0.5">
        <span class="text-slate-400">Domain & Lexical:</span>
        <span class="font-mono text-slate-200">${p.domain_score}%</span>
      </div>
      <div class="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
        <div class="h-full bg-red-500" style="width: ${p.domain_score}%"></div>
      </div>
    </div>
    <div>
      <div class="flex justify-between text-[11px] mb-0.5">
        <span class="text-slate-400">Infrastructure:</span>
        <span class="font-mono text-slate-200">${p.infra_score}%</span>
      </div>
      <div class="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
        <div class="h-full bg-amber-500" style="width: ${p.infra_score}%"></div>
      </div>
    </div>
    <div>
      <div class="flex justify-between text-[11px] mb-0.5">
        <span class="text-slate-400">Visual Logo Mimicry:</span>
        <span class="font-mono text-slate-200">${p.visual_score}%</span>
      </div>
      <div class="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
        <div class="h-full bg-purple-500" style="width: ${p.visual_score}%"></div>
      </div>
    </div>
    <div>
      <div class="flex justify-between text-[11px] mb-0.5">
        <span class="text-slate-400">Lure NLP Scam Intent:</span>
        <span class="font-mono text-slate-200">${p.content_score}%</span>
      </div>
      <div class="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
        <div class="h-full bg-rose-500" style="width: ${p.content_score}%"></div>
      </div>
    </div>
    <div>
      <div class="flex justify-between text-[11px] mb-0.5">
        <span class="text-slate-400">Social Impersonation:</span>
        <span class="font-mono text-slate-200">${p.social_score}%</span>
      </div>
      <div class="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
        <div class="h-full bg-orange-500" style="width: ${p.social_score}%"></div>
      </div>
    </div>
  `;

  // Auto-sync other tabs with selected case data
  syncTabsWithCase(found);
}

function syncTabsWithCase(c) {
  // Domain tab
  const dBrand = document.getElementById('domain-scan-brand-input');
  if (dBrand) dBrand.value = c.target_brand;
  const dSingle = document.getElementById('single-domain-input');
  if (dSingle) dSingle.value = c.primary_threat_domain;

  // Social tab
  if (c.social_impersonation) {
    document.getElementById('social-target-brand').value = c.target_brand;
    document.getElementById('social-platform').value = c.social_impersonation.platform;
    document.getElementById('social-handle').value = c.social_impersonation.handle;
    document.getElementById('social-name').value = c.social_impersonation.display_name;
    document.getElementById('social-bio').value = c.social_impersonation.bio;
    document.getElementById('social-followers').value = c.social_impersonation.followers;
    document.getElementById('social-following').value = c.social_impersonation.following;
    document.getElementById('social-age').value = c.social_impersonation.account_age_days;
  }

  // Communication tab
  if (c.communication_lure) {
    document.getElementById('comm-brand').value = c.target_brand;
    document.getElementById('comm-sender').value = c.communication_lure.sender;
    document.getElementById('comm-body').value = c.communication_lure.message_text;
  }
}

// 2. Domain Scanner
async function runDomainPermutationScan() {
  const brand = document.getElementById('domain-scan-brand-input').value.trim();
  const tld = document.getElementById('domain-scan-tld-select').value;
  if (!brand) return;

  const tbody = document.getElementById('domain-results-tbody');
  tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-slate-500"><i class="fa-solid fa-spinner fa-spin mr-2"></i> Generating permutations and checking DNS/SSL...</td></tr>`;

  try {
    const res = await fetch('/api/scan/domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ brand, tld, check_live: true })
    });
    const data = await res.json();
    document.getElementById('domain-scan-count-badge').innerText = `${data.total_permutations_generated} Permutations Generated`;

    tbody.innerHTML = '';
    data.analyzed_sample.forEach(item => {
      const isCritical = item.risk.severity === 'CRITICAL';
      const isHigh = item.risk.severity === 'HIGH';
      const badgeClass = isCritical ? 'bg-red-500/20 text-red-300 border-red-500/40' : (isHigh ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-slate-800 text-slate-400 border-slate-700');

      const tr = document.createElement('tr');
      tr.className = 'hover:bg-slate-800/40 transition';
      tr.innerHTML = `
        <td class="py-3 px-4 font-bold text-white">${item.domain}</td>
        <td class="py-3 px-4 text-indigo-300 font-sans">${item.attack_type}</td>
        <td class="py-3 px-4 text-slate-400 font-sans">${item.technique}</td>
        <td class="py-3 px-4">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeClass}">
            ${item.risk.risk_score} — ${item.risk.severity}
          </span>
        </td>
        <td class="py-3 px-4 font-mono text-[11px]">
          ${item.dns.resolved ? `<span class="text-emerald-400"><i class="fa-solid fa-circle-check"></i> ${item.dns.ip_addresses[0]}</span>` : `<span class="text-slate-500">Unresolved / Dormant</span>`}
        </td>
        <td class="py-3 px-4 text-right">
          <button onclick="probeDomain('${item.domain}', '${brand}')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-sans">
            Deep Probe
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="py-4 text-center text-red-400">Scan failed: ${err.message}</td></tr>`;
  }
}

async function probeDomain(domain, brand) {
  document.getElementById('single-domain-input').value = domain;
  switchTab('domain');
  await runSingleDomainProbe();
}

async function runSingleDomainProbe() {
  const domain = document.getElementById('single-domain-input').value.trim();
  const brand = document.getElementById('domain-scan-brand-input').value.trim() || 'PayPal';
  if (!domain) return;

  try {
    const res = await fetch('/api/scan/domain/single', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, brand })
    });
    const data = await res.json();
    alert(`[DEEP PROBE COMPLETED: ${domain}]\nRisk Score: ${data.risk.risk_score} (${data.risk.severity})\nResolved IP: ${data.dns.ip_addresses.join(', ') || 'None'}\nSSL Issuer: ${data.ssl.issuer || 'No SSL'}\nEvidence Hash: ${data.evidence_receipt.sha256_hash.substring(0, 16)}...`);
    loadEvidenceLedger();
  } catch (err) {
    alert("Domain probe error: " + err.message);
  }
}

// 3. Visual Matcher
async function runVisualMatchScan() {
  const brandSelect = document.getElementById('visual-brand-select').value;
  const fileInput = document.getElementById('visual-file-input');

  const formData = new FormData();
  formData.append('target_brand', brandSelect);
  if (fileInput.files.length > 0) {
    formData.append('file', fileInput.files[0]);
  }

  try {
    const res = await fetch('/api/scan/visual', {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    const match = data.visual_library_matches.top_match;

    document.getElementById('visual-composite-score').innerText = `${match.composite_visual_score}%`;
    document.getElementById('visual-score-bar').style.width = `${match.composite_visual_score}%`;
    document.getElementById('visual-verdict-badge').innerText = match.verdict;
    document.getElementById('visual-verdict-badge').className = `px-2.5 py-0.5 rounded text-xs font-bold ${
      match.composite_visual_score >= 80 ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
    }`;
    document.getElementById('visual-explanation').innerText = match.explanation;

    document.getElementById('hash-phash-val').innerText = match.hashes.suspect.phash;
    document.getElementById('hash-dhash-val').innerText = match.hashes.suspect.dhash;
    document.getElementById('hash-hamming-val').innerText = `${match.hamming_distances.phash} bits / 64`;
    document.getElementById('hash-color-val').innerText = `${match.color_palette_similarity_pct}%`;

    loadEvidenceLedger();
  } catch (err) {
    alert("Visual matching error: " + err.message);
  }
}

function testPresetVisual(brand) {
  document.getElementById('visual-brand-select').value = brand;
  runVisualMatchScan();
}

// 4. Social Media Detector
async function runSocialAccountScan() {
  const payload = {
    platform: document.getElementById('social-platform').value,
    authentic_brand: document.getElementById('social-target-brand').value,
    authentic_handle: `@${document.getElementById('social-target-brand').value}`,
    handle: document.getElementById('social-handle').value,
    display_name: document.getElementById('social-name').value,
    bio: document.getElementById('social-bio').value,
    followers: parseInt(document.getElementById('social-followers').value) || 0,
    following: parseInt(document.getElementById('social-following').value) || 0,
    account_age_days: parseInt(document.getElementById('social-age').value) || 10,
    is_verified: false
  };

  try {
    const res = await fetch('/api/scan/social', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    const a = data.profile_analysis;

    document.getElementById('social-verdict-badge').innerText = a.verdict;
    document.getElementById('social-verdict-badge').className = `px-2.5 py-0.5 rounded text-xs font-bold ${
      a.impersonation_score >= 80 ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
    }`;
    document.getElementById('social-score-val').innerText = `${a.impersonation_score} / 100`;

    const indContainer = document.getElementById('social-indicators-list');
    indContainer.innerHTML = '';
    a.indicators.forEach(ind => {
      const div = document.createElement('div');
      div.className = 'p-2 bg-slate-900 rounded text-slate-300 flex items-start space-x-2';
      div.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-amber-400 mt-0.5"></i><span>${ind}</span>`;
      indContainer.appendChild(div);
    });

    const predContainer = document.getElementById('social-predictive-handles');
    predContainer.innerHTML = '';
    data.predictive_squatting_handles.forEach(h => {
      const span = document.createElement('span');
      span.className = 'px-2 py-1 bg-slate-900 border border-slate-800 rounded font-mono text-[11px] text-slate-300';
      span.innerText = h.handle;
      predContainer.appendChild(span);
    });

    loadEvidenceLedger();
  } catch (err) {
    alert("Social scan error: " + err.message);
  }
}

// 5. Communication NLP
async function runCommunicationNLPScan() {
  const payload = {
    claimed_brand: document.getElementById('comm-brand').value,
    sender: document.getElementById('comm-sender').value,
    text: document.getElementById('comm-body').value
  };

  try {
    const res = await fetch('/api/scan/communication', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    const a = data.nlp_analysis;

    document.getElementById('comm-verdict-badge').innerText = a.verdict;
    document.getElementById('comm-verdict-badge').className = `px-2.5 py-0.5 rounded text-xs font-bold ${
      a.fraud_score >= 80 ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
    }`;
    document.getElementById('comm-fraud-score').innerText = `${a.fraud_score} / 100`;
    document.getElementById('comm-urgency-score').innerText = `${a.subscores.urgency_coercion} / 45 Pts`;

    const cuesContainer = document.getElementById('comm-cues-list');
    cuesContainer.innerHTML = '';
    a.detected_cues.forEach(cue => {
      const div = document.createElement('div');
      div.className = 'p-2 bg-slate-900 rounded text-slate-300 flex items-start justify-between';
      div.innerHTML = `
        <div>
          <span class="font-semibold text-slate-200 block">${cue.category}</span>
          <span class="text-slate-400 text-[11px]">${cue.description}</span>
        </div>
        <span class="font-mono text-red-400 font-bold text-xs">+${cue.points}</span>
      `;
      cuesContainer.appendChild(div);
    });

    const urlsContainer = document.getElementById('comm-urls-list');
    urlsContainer.innerHTML = '';
    if (a.extracted_urls.length === 0) {
      urlsContainer.innerHTML = `<span class="text-slate-500 text-xs">No embedded URLs found.</span>`;
    } else {
      a.extracted_urls.forEach(u => {
        const div = document.createElement('div');
        div.className = 'p-1.5 bg-slate-900 rounded font-mono text-[11px] text-red-300 flex items-center space-x-1.5';
        div.innerHTML = `<i class="fa-solid fa-link text-red-400"></i><span class="truncate">${u}</span>`;
        urlsContainer.appendChild(div);
      });
    }

    loadEvidenceLedger();
  } catch (err) {
    alert("NLP scan error: " + err.message);
  }
}

// 6. Threat Graph
async function refreshThreatGraph() {
  try {
    const res = await fetch('/api/graph');
    const data = await res.json();
    initCytoscapeGraph(data.graph.elements);

    // Update Pivots
    const pivotsContainer = document.getElementById('graph-top-pivots');
    if (pivotsContainer) {
      pivotsContainer.innerHTML = '';
      (data.metrics.top_infrastructure_pivots || []).slice(0, 6).forEach(p => {
        const div = document.createElement('div');
        div.className = 'p-2 bg-slate-900/60 rounded border border-slate-800 flex justify-between items-center';
        div.innerHTML = `
          <div>
            <span class="text-white font-medium block truncate max-w-[130px]">${p.label}</span>
            <span class="text-[10px] text-slate-500">${p.entity_type}</span>
          </div>
          <span class="px-1.5 py-0.5 bg-indigo-500/10 text-indigo-400 text-[10px] rounded border border-indigo-500/20">
            Deg: ${p.connected_edges}
          </span>
        `;
        pivotsContainer.appendChild(div);
      });
    }

    // Update Top Counters
    const nodeStat = document.getElementById('stat-graph-nodes');
    if (nodeStat) nodeStat.innerText = `${data.metrics.total_nodes} Entities`;
    const syndStat = document.getElementById('stat-syndicates');
    if (syndStat) syndStat.innerText = `${data.metrics.syndicates_count} Clusters`;
  } catch (err) {
    console.error("Failed to refresh graph:", err);
  }
}

// 7. Evidence Ledger
async function loadEvidenceLedger() {
  const tbody = document.getElementById('evidence-ledger-tbody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/evidence');
    const records = await res.json();
    tbody.innerHTML = '';

    records.slice().reverse().forEach((r, idx) => {
      const tr = document.createElement('tr');
      tr.className = 'hover:bg-slate-800/40 transition';
      tr.innerHTML = `
        <td class="py-3 px-4 font-mono text-slate-500">#${r.sequence || idx}</td>
        <td class="py-3 px-4 font-mono text-indigo-400 font-semibold truncate max-w-[120px]">${r.evidence_id}</td>
        <td class="py-3 px-4 font-sans text-slate-300">${r.artifact_type}</td>
        <td class="py-3 px-4 font-mono text-slate-400 truncate max-w-[150px]">${r.target_uri}</td>
        <td class="py-3 px-4 font-mono text-[11px] text-emerald-400 truncate max-w-[130px]">${r.sha256_hash}</td>
        <td class="py-3 px-4 font-mono text-[11px] text-slate-400">${(r.timestamp_utc || '').replace('T', ' ').substring(0, 19)}</td>
        <td class="py-3 px-4 text-right">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            SEALED
          </span>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load evidence ledger:", err);
  }
}

async function verifyEvidenceSeal() {
  const evId = document.getElementById('verify-evidence-id').value.trim();
  if (!evId) return alert("Please enter an Evidence UUID");

  try {
    const res = await fetch('/api/evidence');
    const records = await res.json();
    const found = records.find(r => r.evidence_id === evId);
    if (!found) return alert("Evidence ID not found in ledger!");

    alert(`[VERIFIED FORENSIC PROVENANCE]\nEvidence ID: ${found.evidence_id}\nArtifact: ${found.artifact_type}\nSHA-256 Digest: ${found.sha256_hash}\nTimestamp: ${found.timestamp_utc}\nHMAC Seal: ${found.hmac_seal}\nLedger Block Hash: ${found.block_hash}\nStatus: ADMISSIBLE & TAMPER-FREE`);
  } catch (err) {
    alert("Verification error: " + err.message);
  }
}

// 8. Takedown & Dossier Generator
async function generateFreshReport() {
  if (!currentCase) {
    if (allCases.length > 0) selectCase(allCases[0].case_id);
    else return alert("No active case selected.");
  }

  const payload = {
    case_id: currentCase.case_id,
    brand_name: currentCase.target_brand,
    investigator: "AegisOSINT Lead Analyst (Incident Response Unit)",
    target_entity: currentCase.primary_threat_domain,
    risk_summary: currentCase.precalculated_risk,
    iocs: {
      domains: currentCase.associated_domains,
      ip_addresses: currentCase.infrastructure.ip_addresses,
      nameservers: currentCase.infrastructure.nameservers,
      social_handles: currentCase.social_impersonation ? [currentCase.social_impersonation.handle] : [],
      crypto_wallets: currentCase.crypto_wallet ? [currentCase.crypto_wallet] : []
    }
  };

  try {
    const res = await fetch('/api/report/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    currentDossier = data.dossier;
    currentSTIX = data.stix21_bundle;

    document.getElementById('report-exec-summary').innerText = data.dossier.executive_summary;
    document.getElementById('report-case-id').innerText = data.dossier.case_id;
    document.getElementById('report-threat-tier').innerText = `${data.dossier.threat_assessment.severity} (${data.dossier.threat_assessment.risk_score}/100)`;
    document.getElementById('report-takedown-textarea').value = data.dossier.takedowns.registrar_abuse_letter;

    const iocsBox = document.getElementById('report-iocs-box');
    iocsBox.innerHTML = `
      <div><strong>Domains:</strong> ${data.dossier.indicators_of_compromise.domains.join(', ')}</div>
      <div><strong>Host IPs:</strong> ${data.dossier.indicators_of_compromise.ip_addresses.join(', ')}</div>
      <div><strong>Nameservers:</strong> ${data.dossier.indicators_of_compromise.nameservers.join(', ')}</div>
      <div><strong>Social Handles:</strong> ${data.dossier.indicators_of_compromise.social_handles.join(', ')}</div>
      ${data.dossier.indicators_of_compromise.crypto_wallets ? `<div><strong>Drainer Wallet:</strong> ${data.dossier.indicators_of_compromise.crypto_wallets.join(', ')}</div>` : ''}
    `;

    switchTab('report');
  } catch (err) {
    alert("Dossier generation error: " + err.message);
  }
}

function copyTakedownText() {
  const ta = document.getElementById('report-takedown-textarea');
  ta.select();
  document.execCommand('copy');
  alert("ICANN Takedown Notice copied to clipboard!");
}

function downloadSTIX() {
  if (!currentSTIX) {
    generateFreshReport().then(() => downloadSTIX());
    return;
  }
  const blob = new Blob([JSON.stringify(currentSTIX, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `STIX21_${currentCase ? currentCase.case_id : 'threat_bundle'}.json`;
  a.click();
}

// Convenient helper to trigger end-to-end triage
async function populateAndTestAll() {
  if (!currentCase) return;
  alert(`Starting Automated Multi-Vector Triage for ${currentCase.target_brand}...\nAnalyzing domain permutations, computing logo visual hashes, scanning social handle, and dissecting communication payload.`);
  await runDomainPermutationScan();
  await runVisualMatchScan();
  await runSocialAccountScan();
  await runCommunicationNLPScan();
  await generateFreshReport();
}

// 9. OSINT Framework & Deep Recon Toolkit
async function runCTLogRecon() {
  const query = document.getElementById('recon-ct-query').value.trim();
  const container = document.getElementById('recon-ct-results');
  if (!query) return;

  container.innerHTML = '<span class="text-cyan-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Querying crt.sh Certificate Transparency logs...</span>';

  try {
    const res = await fetch('/api/recon/ct-logs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, limit: 12 })
    });
    const data = await res.json();
    container.innerHTML = '';
    if (data.certificates.length === 0) {
      container.innerHTML = '<span class="text-slate-500">No public CT certificates found.</span>';
    } else {
      data.certificates.forEach(c => {
        const div = document.createElement('div');
        div.className = 'p-1.5 bg-slate-950 rounded flex justify-between items-center text-[11px] border border-slate-800';
        div.innerHTML = `
          <div>
            <span class="text-cyan-300 font-bold block truncate max-w-[280px]">${c.subdomain}</span>
            <span class="text-[10px] text-slate-500">${c.issuer_name}</span>
          </div>
          <span class="text-[10px] text-slate-400 font-mono">${(c.logged_at || '').substring(0, 10)}</span>
        `;
        container.appendChild(div);
      });
    }
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">CT Log error: ${err.message}</span>`;
  }
}

async function runWaybackRecon() {
  const domain = document.getElementById('recon-wayback-domain').value.trim();
  const container = document.getElementById('recon-wayback-results');
  if (!domain) return;

  container.innerHTML = '<span class="text-amber-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Querying Internet Archive CDX...</span>';

  try {
    const res = await fetch('/api/recon/wayback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, limit: 10 })
    });
    const data = await res.json();
    container.innerHTML = `
      <div class="p-2 bg-slate-950 rounded border border-slate-800 text-xs mb-1">
        <span class="font-bold ${data.is_freshly_staged_zero_history ? 'text-red-400' : 'text-amber-400'} block">
          ${data.forensic_verdict}
        </span>
        <span class="text-slate-400 text-[11px]">First seen snapshot: ${data.first_seen_date} | Total archives: ${data.snapshot_count}</span>
      </div>
    `;
    data.snapshots.slice(0, 4).forEach(s => {
      const div = document.createElement('div');
      div.className = 'p-1 bg-slate-900 rounded font-mono text-[11px] flex justify-between text-slate-300';
      div.innerHTML = `
        <span>${s.date} [Status: ${s.status}]</span>
        <a href="${s.archive_view}" target="_blank" class="text-indigo-400 hover:underline">View Snapshot &rarr;</a>
      `;
      container.appendChild(div);
    });
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">Wayback error: ${err.message}</span>`;
  }
}

async function runHandleFootprintRecon() {
  const handle = document.getElementById('recon-handle-input').value.trim();
  const container = document.getElementById('recon-handle-results');
  if (!handle) return;

  container.innerHTML = '<span class="text-purple-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Probing 9 target social networks...</span>';

  try {
    const res = await fetch('/api/recon/username-footprint', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ handle })
    });
    const data = await res.json();
    container.innerHTML = '';
    data.footprint.forEach(item => {
      const div = document.createElement('div');
      div.className = 'p-1.5 bg-slate-950 rounded flex justify-between items-center border border-slate-800 text-[11px]';
      div.innerHTML = `
        <div>
          <span class="text-white font-bold">${item.platform}</span>
          <span class="text-[10px] text-slate-500 ml-1">(${item.category})</span>
        </div>
        <a href="${item.profile_url}" target="_blank" class="text-purple-400 hover:underline truncate max-w-[180px]">${item.profile_url}</a>
      `;
      container.appendChild(div);
    });
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">Handle footprint error: ${err.message}</span>`;
  }
}

async function runEmailRecon() {
  const email = document.getElementById('recon-email-input').value.trim();
  const container = document.getElementById('recon-email-results');
  if (!email) return;

  container.innerHTML = '<span class="text-rose-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Analyzing email provider reputation...</span>';

  try {
    const res = await fetch('/api/recon/scammer-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const data = await res.json();
    container.innerHTML = `
      <div class="p-2 bg-slate-950 rounded border border-slate-800 flex justify-between items-center mb-1">
        <span class="text-white font-mono">${data.email}</span>
        <span class="px-2 py-0.5 rounded text-[10px] font-bold ${data.risk_score >= 50 ? 'bg-red-500/20 text-red-300 border border-red-500/40' : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'}">
          ${data.risk_score} / 100 (${data.severity})
        </span>
      </div>
      <div class="space-y-1">
        ${data.indicators.map(ind => `<div class="text-[11px] text-rose-300 flex items-center space-x-1"><i class="fa-solid fa-circle-exclamation text-rose-400 text-[9px]"></i><span>${ind}</span></div>`).join('')}
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">Email recon error: ${err.message}</span>`;
  }
}

async function runCloakingC2Detector() {
  const html_content = document.getElementById('recon-c2-html').value;
  const container = document.getElementById('recon-c2-results');
  container.innerHTML = '<span class="text-indigo-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Dissecting form actions and cloaking scripts...</span>';

  try {
    const res = await fetch('/api/recon/cloaking-form-c2', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ html_content, domain: "phishing-sample.top" })
    });
    const data = await res.json();
    container.innerHTML = `
      <div class="p-2 bg-slate-950 rounded border border-slate-800 text-xs">
        <div class="flex justify-between items-center mb-1">
          <span class="font-bold ${data.is_stealth_phishing_kit ? 'text-red-400' : 'text-emerald-400'}">
            ${data.is_stealth_phishing_kit ? 'CONFIRMED STEALTH PHISHING KIT' : 'NO EVASION DETECTED'}
          </span>
          <span class="font-mono text-red-400 font-bold">${data.exfiltration_risk_score} / 100</span>
        </div>
        ${data.c2_exfiltration_threats.map(c => `
          <div class="text-[11px] text-amber-300 mt-1">
            <strong>Exfiltration C2:</strong> ${c.exfiltration_type} (${c.action_url})
          </div>
        `).join('')}
        ${data.cloaking_evasion_tactics.map(cl => `
          <div class="text-[11px] text-slate-400 mt-0.5">• ${cl}</div>
        `).join('')}
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">Cloaking detector error: ${err.message}</span>`;
  }
}

async function runXAIExplain() {
  const container = document.getElementById('recon-xai-results');
  if (!container) return;

  const currentWeights = currentCase ? {
    "Domain Typosquat / Combosquat Similarity": currentCase.precalculated_risk.domain_score * 0.25,
    "Ephemeral Certificate / Hosting ASN": currentCase.precalculated_risk.infra_score * 0.20,
    "Cloned Logo Perceptual Hash Mimicry": currentCase.precalculated_risk.visual_score * 0.20,
    "Psychological Coercion NLP Score": currentCase.precalculated_risk.content_score * 0.15,
    "Social Media Impersonation / Fake Badging": currentCase.precalculated_risk.social_score * 0.10,
    "Syndicate Graph Topological Degree Hub": currentCase.precalculated_risk.graph_score * 0.10
  } : {
    "Combosquat Keyword Affix": 23.5,
    "Let's Encrypt Free Ephemeral Issuer": 18.0,
    "pHash Hamming Distance < 8 bits": 24.0,
    "24h Deadline / Account Lock Urgency": 14.5,
    "Emoji Checkmark Spoofing": 9.0
  };

  try {
    const res = await fetch('/api/recon/explain-xai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ features: currentWeights })
    });
    const data = await res.json();
    container.innerHTML = '';
    data.attributions.forEach(a => {
      const div = document.createElement('div');
      div.className = 'p-1.5 bg-slate-950 rounded flex justify-between items-center text-[11px] border border-slate-800';
      div.innerHTML = `
        <span class="text-slate-300 truncate max-w-[250px]">${a.feature}</span>
        <div class="flex items-center space-x-2 font-mono">
          <span class="text-emerald-400 font-bold">+${a.weight_contribution} pts</span>
          <span class="px-1.5 py-0.2 rounded text-[9px] bg-red-500/10 text-red-400 border border-red-500/20">${a.impact_tier}</span>
        </div>
      `;
      container.appendChild(div);
    });
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">XAI error: ${err.message}</span>`;
  }
}

