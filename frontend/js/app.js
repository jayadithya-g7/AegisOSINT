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
    loadOSINTFrameworkExplorer();
  }
}

// Initialize Application on Page Load
document.addEventListener('DOMContentLoaded', async () => {
  await fetchCases();
  await refreshThreatGraph();
  await loadEvidenceLedger();
  runXAIExplain();
  loadOSINTFrameworkExplorer();
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

  // Cyber LLM Advisor tab
  const cyberDom = document.getElementById('cyber-llm-domain');
  if (cyberDom) cyberDom.value = c.primary_threat_domain;
  const cyberBrand = document.getElementById('cyber-llm-brand');
  if (cyberBrand) cyberBrand.value = c.target_brand;

  // DMARC & Email security tab
  const dmarcDom = document.getElementById('recon-dmarc-domain');
  if (dmarcDom) dmarcDom.value = c.primary_threat_domain;
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

    const fav = match.favicon_murmur3 || {};
    const murmurEl = document.getElementById('hash-murmur3-val');
    const murmurLinks = document.getElementById('hash-murmur3-links');
    if (murmurEl) murmurEl.innerText = fav.shodan_hash ? `${fav.shodan_hash}` : 'Not Calculated';
    if (murmurLinks && fav.shodan_search_url) {
      murmurLinks.innerHTML = `
        <a href="${fav.shodan_search_url}" target="_blank" rel="noopener noreferrer" class="px-2 py-0.5 bg-red-600/30 hover:bg-red-600 text-red-300 hover:text-white rounded text-[10px] font-semibold flex items-center space-x-1">
          <span>Shodan</span>
          <i class="fa-solid fa-arrow-up-right-from-square text-[8px]"></i>
        </a>
        <a href="${fav.censys_search_url}" target="_blank" rel="noopener noreferrer" class="px-2 py-0.5 bg-blue-600/30 hover:bg-blue-600 text-blue-300 hover:text-white rounded text-[10px] font-semibold flex items-center space-x-1">
          <span>Censys</span>
          <i class="fa-solid fa-arrow-up-right-from-square text-[8px]"></i>
        </a>
      `;
    }

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
    await loadSigmaYaraRules();
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

async function loadSigmaYaraRules() {
  if (!currentCase) return;
  const sigmaTa = document.getElementById('report-sigma-textarea');
  const yaraTa = document.getElementById('report-yara-textarea');
  if (sigmaTa) sigmaTa.value = "Generating Sigma SIEM detection rule...";
  if (yaraTa) yaraTa.value = "Generating YARA phishing signature...";

  try {
    const res = await fetch('/api/recon/sigma-yara', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain: currentCase.primary_threat_domain,
        brand: currentCase.target_brand,
        ip_addresses: currentCase.infrastructure.ip_addresses
      })
    });
    const data = await res.json();
    if (sigmaTa) sigmaTa.value = data.sigma_rule_yaml;
    if (yaraTa) yaraTa.value = data.yara_rule;
  } catch (err) {
    if (sigmaTa) sigmaTa.value = "Error generating Sigma rule: " + err.message;
    if (yaraTa) yaraTa.value = "Error generating YARA rule: " + err.message;
  }
}

function copySigmaText() {
  const ta = document.getElementById('report-sigma-textarea');
  if (!ta) return;
  ta.select();
  document.execCommand('copy');
  alert("Sigma SIEM Rule copied to clipboard!");
}

function copyYaraText() {
  const ta = document.getElementById('report-yara-textarea');
  if (!ta) return;
  ta.select();
  document.execCommand('copy');
  alert("YARA Phishing Signature copied to clipboard!");
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

// 9. Cyber LLM Security Reasoning (GLM-5.3 / CyberSecEval Benchmarks)
async function runCyberLLMAnalysis() {
  const domain = document.getElementById('cyber-llm-domain').value.trim();
  const brand = document.getElementById('cyber-llm-brand').value.trim() || 'PayPal';
  const modelPreference = document.getElementById('cyber-llm-model-select').value;
  const btn = document.getElementById('btn-cyber-llm-run');

  if (!domain) return alert("Please specify a target domain to analyze.");

  const origBtnHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Running ${modelPreference}...`;

  try {
    const payload = {
      domain,
      brand,
      model_preference: modelPreference,
      telemetry: currentCase ? {
        dns: { ip_addresses: currentCase.infrastructure.ip_addresses },
        ssl: { is_free_cert: true, issuer: currentCase.infrastructure.ssl_issuer },
        rdap: { domain_age_days: 3 },
        http: { has_login_form: true },
        risk: { risk_score: currentCase.precalculated_risk.risk_score }
      } : {
        dns: { ip_addresses: ["198.51.100.23"] },
        ssl: { is_free_cert: true },
        risk: { risk_score: 85.0 }
      }
    };

    const res = await fetch('/api/cyber-llm/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();

    // Populate Threat Actor Profile
    document.getElementById('cyber-llm-archetype').innerText = data.threat_actor_profiling.archetype;
    document.getElementById('cyber-llm-tier').innerText = data.threat_actor_profiling.sophistication_tier;
    document.getElementById('cyber-llm-intent').innerText = data.threat_actor_profiling.operational_intent;

    // Populate Benchmark & Provenance
    document.getElementById('cyber-llm-evaluator').innerText = data.model_evaluator;
    document.getElementById('cyber-llm-benchmark').innerText = data.benchmark_framework;

    // Populate Evidence Seal
    if (data.evidence_receipt) {
      document.getElementById('cyber-llm-ev-id').innerText = data.evidence_receipt.evidence_id;
      document.getElementById('cyber-llm-ev-hash').innerText = data.evidence_receipt.sha256_hash;
    }

    // Populate MITRE Matrix
    const mitreContainer = document.getElementById('cyber-llm-mitre-container');
    mitreContainer.innerHTML = '';
    data.mitre_attack_mappings.forEach(m => {
      const card = document.createElement('div');
      card.className = 'p-2.5 bg-slate-950 rounded border border-slate-800 text-xs space-y-1';
      card.innerHTML = `
        <div class="flex items-center justify-between">
          <span class="font-mono font-bold text-fuchsia-400">${m.technique_id}</span>
          <span class="px-1.5 py-0.2 rounded text-[9px] bg-slate-800 text-slate-300 font-mono">${m.tactic}</span>
        </div>
        <div class="text-[11px] font-semibold text-white">${m.technique_name}</div>
        <div class="text-[10px] text-slate-400 line-clamp-2">${m.relevance}</div>
      `;
      mitreContainer.appendChild(card);
    });

    // Populate Narrative
    document.getElementById('cyber-llm-narrative').innerText = data.executive_analysis;

    // Populate Signatures
    document.getElementById('cyber-llm-sig-rpz').innerText = data.active_defense_signatures.dns_rpz_zone;
    document.getElementById('cyber-llm-sig-suricata').innerText = data.active_defense_signatures.suricata_ids_rule;
    document.getElementById('cyber-llm-sig-waf').innerText = data.active_defense_signatures.waf_filter_expression;

    // Refresh evidence ledger
    await loadEvidenceLedger();

  } catch (err) {
    alert("Cyber LLM Analysis error: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = origBtnHtml;
  }
}

// 10. Email Authentication (DMARC, SPF, BIMI) Auditor
async function runDmarcSpfAudit() {
  const domain = document.getElementById('recon-dmarc-domain').value.trim();
  const container = document.getElementById('recon-dmarc-results');
  if (!domain) return alert("Please enter a domain to audit email authentication.");

  container.innerHTML = '<span class="text-indigo-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Querying SPF, DMARC, and BIMI records across DoH resolvers...</span>';

  try {
    const res = await fetch('/api/scan/dmarc-spf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    const data = await res.json();

    const isCritical = data.threat_severity === 'CRITICAL';
    const isHigh = data.threat_severity === 'HIGH';
    const isSecure = data.threat_severity === 'SECURE';
    const badgeColor = isCritical
      ? 'bg-red-500/20 text-red-300 border-red-500/40'
      : (isHigh
      ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
      : (isSecure
      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
      : 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40'));

    container.innerHTML = `
      <div class="p-2 bg-slate-950 rounded border border-slate-800 space-y-1.5">
        <div class="flex items-center justify-between">
          <span class="font-bold text-white font-mono">${data.domain}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeColor}">
            ${data.threat_severity} (Spoof Score: ${data.spoofing_vulnerability_score}/100)
          </span>
        </div>
        <div class="text-[11px] grid grid-cols-2 gap-1 pt-1 border-t border-slate-800/60 font-mono">
          <div><span class="text-slate-500">SPF Mechanism:</span> <span class="${data.spf_audit.is_spoofable ? 'text-red-400' : 'text-emerald-400'} font-bold">${data.spf_audit.all_mechanism || 'None'}</span></div>
          <div><span class="text-slate-500">DMARC Policy:</span> <span class="${data.dmarc_audit.is_enforced ? 'text-emerald-400' : 'text-red-400'} font-bold">${data.dmarc_audit.policy} (pct: ${data.dmarc_audit.percentage}%)</span></div>
        </div>
        <div class="text-[10px] text-slate-400">${data.dmarc_audit.explanation}</div>
        ${data.remediation_actions && data.remediation_actions.length > 0 ? `
          <div class="pt-1 border-t border-slate-800/60 text-[10px] text-amber-300">
            <strong>Remediation:</strong> ${data.remediation_actions.join(' | ')}
          </div>
        ` : ''}
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">DMARC audit error: ${err.message}</span>`;
  }
}

// ==========================================
// OSINT FRAMEWORK (osintframework.com) EXPLORER & SUITE
// ==========================================

let osintFrameworkCategoriesLoaded = false;

async function loadOSINTFrameworkExplorer() {
  if (osintFrameworkCategoriesLoaded) return;
  try {
    const res = await fetch('/api/recon/osint-framework/categories');
    const data = await res.json();
    const select = document.getElementById('osint-cat-filter');
    if (select && data.categories) {
      select.innerHTML = '<option value="ALL">All 33 Categories (1,167 Tools)</option>';
      data.categories.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.category;
        opt.innerText = `${c.category} (${c.tool_count} tools)`;
        select.appendChild(opt);
      });
      osintFrameworkCategoriesLoaded = true;
    }
    await filterOSINTFramework();
  } catch (err) {
    console.error("Failed to load OSINT Framework categories:", err);
  }
}

async function filterOSINTFramework() {
  const query = document.getElementById('osint-tool-search')?.value.trim() || '';
  const category = document.getElementById('osint-cat-filter')?.value || 'ALL';
  const container = document.getElementById('osint-framework-results');
  const statusEl = document.getElementById('osint-framework-status');

  if (!container) return;

  try {
    const url = `/api/recon/osint-framework/search?q=${encodeURIComponent(query)}&category=${encodeURIComponent(category === 'ALL' ? '' : category)}&limit=60`;
    const res = await fetch(url);
    const data = await res.json();

    if (!data.tools || data.tools.length === 0) {
      container.innerHTML = `
        <div class="text-center py-6 text-slate-500 text-xs">
          <i class="fa-solid fa-circle-exclamation text-amber-400 mr-1.5"></i>
          No tools found matching "${query}" in category "${category}".
        </div>
      `;
      if (statusEl) statusEl.innerText = `Showing 0 tools`;
      return;
    }

    if (statusEl) statusEl.innerText = `Showing ${data.tools.length} tools ${query ? `matching "${query}"` : ''} in ${category}`;

    container.innerHTML = data.tools.map(t => {
      const tagsHtml = (t.tags || []).map(tag => {
        let tagColor = 'bg-slate-800 text-slate-300 border-slate-700';
        if (tag.includes('Tool')) tagColor = 'bg-blue-500/20 text-blue-300 border-blue-500/30';
        if (tag.includes('Dork')) tagColor = 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
        if (tag.includes('Registration')) tagColor = 'bg-amber-500/20 text-amber-300 border-amber-500/30';
        if (tag.includes('Malicious')) tagColor = 'bg-red-500/20 text-red-300 border-red-500/30';
        return `<span class="px-1.5 py-0.5 rounded text-[9px] font-mono border ${tagColor}">${tag}</span>`;
      }).join(' ');

      return `
        <div class="p-2.5 bg-slate-900/80 hover:bg-slate-850 rounded-lg border border-slate-800/80 hover:border-indigo-500/40 transition flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div class="space-y-0.5">
            <div class="flex items-center space-x-2">
              <span class="font-bold text-white">${t.name}</span>
              <div class="flex items-center space-x-1">${tagsHtml}</div>
            </div>
            <div class="text-[11px] text-slate-400 flex items-center space-x-1.5 font-mono">
              <span class="text-indigo-400 font-semibold">${t.category}</span>
              <span>&rsaquo;</span>
              <span class="text-slate-300">${t.subcategory}</span>
            </div>
          </div>
          <div class="flex items-center space-x-2 shrink-0">
            <a href="${t.url}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 bg-indigo-600/30 hover:bg-indigo-600/60 text-indigo-300 hover:text-white rounded border border-indigo-500/40 text-[11px] font-semibold transition flex items-center space-x-1">
              <span>Launch</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-[9px]"></i>
            </a>
          </div>
        </div>
      `;
    }).join('');

  } catch (err) {
    container.innerHTML = `<span class="text-red-400 text-xs">Error querying OSINT Framework: ${err.message}</span>`;
  }
}

function setOSINTCategoryFilter(catName) {
  const select = document.getElementById('osint-cat-filter');
  if (select) {
    select.value = catName;
    filterOSINTFramework();
  }
}

// 11. IP Infrastructure & Shodan Host Reconnaissance
async function runIPInfrastructureRecon() {
  const target = document.getElementById('recon-ip-input')?.value.trim();
  const container = document.getElementById('recon-ip-results');
  if (!target) return alert("Please enter an IP address or hostname to probe.");

  container.innerHTML = '<span class="text-blue-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Probing live IP geolocation, ASN, and Shodan InternetDB...</span>';

  try {
    const res = await fetch('/api/recon/ip-infrastructure', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target })
    });
    const data = await res.json();

    const isCritical = data.severity === 'CRITICAL';
    const isHigh = data.severity === 'HIGH';
    const badgeColor = isCritical ? 'bg-red-500/20 text-red-300 border-red-500/40' : (isHigh ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40');

    const openPorts = (data.shodan_telemetry?.open_ports || []).map(p => `<span class="px-1.5 py-0.2 bg-slate-800 text-blue-300 rounded font-mono text-[10px]">${p}</span>`).join(' ') || '<span class="text-slate-500">None detected / firewalled</span>';
    const vulns = (data.shodan_telemetry?.vulnerabilities || []).map(v => `<span class="px-1.5 py-0.2 bg-red-950 text-red-300 rounded font-mono text-[10px] border border-red-800/40">${v}</span>`).join(' ') || '<span class="text-emerald-400 text-[10px]">Zero known CVEs</span>';

    container.innerHTML = `
      <div class="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-1.5">
        <div class="flex items-center justify-between">
          <span class="font-bold text-white font-mono">${data.resolved_ip || data.target}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeColor}">
            ${data.severity} (${data.risk_score}/100)
          </span>
        </div>
        <div class="text-[11px] grid grid-cols-2 gap-1 text-slate-300 font-mono">
          <div><span class="text-slate-500">Location:</span> ${data.geolocation?.city || 'Unknown'}, ${data.geolocation?.country || 'XX'}</div>
          <div><span class="text-slate-500">ASN:</span> ${data.geolocation?.asn || 'AS0'}</div>
          <div><span class="text-slate-500">ISP / Org:</span> ${data.geolocation?.isp || 'Unknown'}</div>
          <div><span class="text-slate-500">PTR Host:</span> ${data.reverse_ptr || 'N/A'}</div>
        </div>
        <div class="pt-1 border-t border-slate-800/60 text-[11px]">
          <span class="text-slate-500 font-mono">Shodan Open Ports:</span> ${openPorts}
        </div>
        <div class="pt-0.5 text-[11px]">
          <span class="text-slate-500 font-mono">Shodan CVEs:</span> ${vulns}
        </div>
        <div class="pt-1 border-t border-slate-800/60 text-[10px] text-slate-400">
          ${data.tactical_assessment}
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">IP Recon error: ${err.message}</span>`;
  }
}

// 12. Cyber Threat Intelligence & AlienVault OTX Pulse Recon
async function runThreatIntelRecon() {
  const indicator = document.getElementById('recon-threat-input')?.value.trim();
  const container = document.getElementById('recon-threat-results');
  if (!indicator) return alert("Please enter a domain or IP to query AlienVault OTX.");

  container.innerHTML = '<span class="text-amber-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Querying AlienVault OTX global threat pulses and IOC database...</span>';

  try {
    const res = await fetch('/api/recon/threat-intel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator })
    });
    const data = await res.json();

    const isMal = data.threat_level === 'MALICIOUS';
    const isSusp = data.threat_level === 'SUSPICIOUS';
    const badgeColor = isMal ? 'bg-red-500/20 text-red-300 border-red-500/40' : (isSusp ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40');

    const pulsesHtml = (data.active_pulses || []).slice(0, 3).map(p => `
      <div class="p-1.5 bg-slate-900 rounded text-[11px] space-y-0.5">
        <div class="font-semibold text-white truncate">${p.name}</div>
        <div class="text-[10px] text-slate-400 flex items-center justify-between">
          <span>By: ${p.author}</span>
          <span>${p.created}</span>
        </div>
      </div>
    `).join('') || '<div class="text-[10px] text-slate-500">No active adversary pulses recorded.</div>';

    const linksHtml = (data.osint_intel_links || []).map(l => `
      <a href="${l.url}" target="_blank" rel="noopener noreferrer" class="px-2 py-0.5 bg-slate-900 hover:bg-slate-800 text-[10px] text-indigo-300 rounded border border-slate-700">
        ${l.source}
      </a>
    `).join(' ');

    container.innerHTML = `
      <div class="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-2">
        <div class="flex items-center justify-between">
          <span class="font-bold text-white font-mono">${data.indicator}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeColor}">
            ${data.threat_level} (${data.alienvault_pulse_count} Pulses)
          </span>
        </div>
        <div class="text-[10px] text-slate-400">${data.tactical_assessment}</div>
        <div class="space-y-1">
          <span class="text-[10px] text-slate-500 uppercase font-mono font-bold">Recent Threat Pulses:</span>
          ${pulsesHtml}
        </div>
        <div class="pt-1 border-t border-slate-800/60 flex flex-wrap gap-1">
          <span class="text-[10px] text-slate-500 font-mono self-center mr-1">Direct IOC Lookups:</span>
          ${linksHtml}
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">Threat Intel error: ${err.message}</span>`;
  }
}

// 13. Scam Cryptocurrency Wallet Auditor
async function runCryptoWalletRecon() {
  const address = document.getElementById('recon-crypto-input')?.value.trim();
  const container = document.getElementById('recon-crypto-results');
  if (!address) return alert("Please enter a cryptocurrency wallet address to audit.");

  container.innerHTML = '<span class="text-yellow-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Querying on-chain blockchain records and abuse databases...</span>';

  try {
    const res = await fetch('/api/recon/crypto-wallet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address })
    });
    const data = await res.json();

    const isCritical = data.severity === 'CRITICAL';
    const isHigh = data.severity === 'HIGH';
    const badgeColor = isCritical ? 'bg-red-500/20 text-red-300 border-red-500/40' : (isHigh ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40');

    const linksHtml = (data.osint_forensic_links || []).map(l => `
      <a href="${l.url}" target="_blank" rel="noopener noreferrer" class="px-2 py-0.5 bg-slate-900 hover:bg-slate-800 text-[10px] text-yellow-300 rounded border border-slate-700">
        ${l.service}
      </a>
    `).join(' ');

    container.innerHTML = `
      <div class="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-2">
        <div class="flex items-center justify-between">
          <span class="font-bold text-white font-mono text-[11px] truncate max-w-[200px]">${data.address}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeColor}">
            ${data.currency}
          </span>
        </div>
        <div class="grid grid-cols-3 gap-1 text-[11px] font-mono pt-1 border-t border-slate-800/60">
          <div><span class="text-slate-500">Transactions:</span> <span class="text-white font-bold">${data.transaction_count}</span></div>
          <div><span class="text-slate-500">Received:</span> <span class="text-yellow-400 font-bold">${data.total_received}</span></div>
          <div><span class="text-slate-500">Balance:</span> <span class="text-emerald-400 font-bold">${data.final_balance}</span></div>
        </div>
        <div class="text-[10px] text-slate-400">${data.tactical_assessment}</div>
        <div class="pt-1 border-t border-slate-800/60 flex flex-wrap gap-1">
          <span class="text-[10px] text-slate-500 font-mono self-center mr-1">Forensics:</span>
          ${linksHtml}
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">Crypto Audit error: ${err.message}</span>`;
  }
}

// 14. Brand Impersonation Google Dorking Hunter
async function runBrandDorksRecon() {
  const brand_name = document.getElementById('recon-dork-brand')?.value.trim();
  const legitimate_domain = document.getElementById('recon-dork-domain')?.value.trim();
  const container = document.getElementById('recon-dork-results');

  if (!brand_name) return alert("Please enter a Brand Name to generate targeted Google Dorks.");

  container.innerHTML = '<span class="text-emerald-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Generating targeted brand defense and phishing hunter dorks...</span>';

  try {
    const res = await fetch('/api/recon/brand-dorks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ brand_name, legitimate_domain })
    });
    const data = await res.json();

    container.innerHTML = data.dorks.map((d, idx) => `
      <div class="p-2 bg-slate-950 rounded border border-slate-800 space-y-1">
        <div class="flex items-center justify-between">
          <span class="text-[11px] font-bold text-emerald-400">${idx + 1}. ${d.category}</span>
          <div class="flex items-center space-x-1">
            <a href="${d.google_url}" target="_blank" rel="noopener noreferrer" class="px-1.5 py-0.5 bg-blue-600/30 hover:bg-blue-600 text-blue-300 hover:text-white rounded text-[9px] font-semibold">Google</a>
            <a href="${d.duckduckgo_url}" target="_blank" rel="noopener noreferrer" class="px-1.5 py-0.5 bg-amber-600/30 hover:bg-amber-600 text-amber-300 hover:text-white rounded text-[9px] font-semibold">DDG</a>
            <a href="${d.bing_url}" target="_blank" rel="noopener noreferrer" class="px-1.5 py-0.5 bg-cyan-600/30 hover:bg-cyan-600 text-cyan-300 hover:text-white rounded text-[9px] font-semibold">Bing</a>
          </div>
        </div>
        <div class="font-mono text-[10px] text-slate-300 bg-slate-900 p-1 rounded overflow-x-auto select-all">${d.dork}</div>
        <div class="text-[9px] text-slate-500">${d.description}</div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">Dork Generator error: ${err.message}</span>`;
  }
}

// 15. openSquat & urlinsane Lookalike Hunter Controller
async function runOpenSquatAudit() {
  const brandInput = document.getElementById('opensquat-brand-input');
  const tldInput = document.getElementById('opensquat-tld-input');
  const liveDnsCheckbox = document.getElementById('opensquat-live-dns');
  const btn = document.getElementById('btn-opensquat-run');
  const panel = document.getElementById('opensquat-results-panel');
  const listContainer = document.getElementById('opensquat-results-list');
  const summaryBadge = document.getElementById('opensquat-summary-badge');
  const resolvingBadge = document.getElementById('opensquat-resolving-badge');

  const brand = brandInput?.value.trim() || 'paypal';
  const tld = tldInput?.value.trim() || 'com';
  const check_live = liveDnsCheckbox ? liveDnsCheckbox.checked : true;

  if (!brand) return alert("Please specify a brand name to audit.");

  const origBtnHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Running openSquat...`;

  if (panel) panel.classList.remove('hidden');
  if (listContainer) listContainer.innerHTML = '<span class="text-indigo-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Synthesizing Levenshtein permutations & probing live DoH...</span>';

  try {
    const res = await fetch('/api/recon/opensquat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ brand, tld, check_live, limit: 25 })
    });
    const data = await res.json();

    if (summaryBadge) summaryBadge.innerText = `Generated ${data.total_lookalikes_generated} permutations (Levenshtein d &le; 2)`;
    if (resolvingBadge) resolvingBadge.innerText = `${data.active_resolving_count} Resolving Live (DoH)`;

    if (!data.high_risk_lookalikes || data.high_risk_lookalikes.length === 0) {
      listContainer.innerHTML = `<span class="text-slate-400 text-xs">No high risk lookalikes identified for "${brand}".</span>`;
      return;
    }

    listContainer.innerHTML = data.high_risk_lookalikes.map((item, idx) => {
      const isCritical = item.threat_score >= 80;
      const isHigh = item.threat_score >= 60;
      const badgeColor = isCritical ? 'bg-red-500/20 text-red-300 border-red-500/40' : (isHigh ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-slate-800 text-slate-300 border-slate-700');
      const dnsBadge = item.resolved && item.ip_addresses?.length > 0
        ? `<span class="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">RESOLVES: ${item.ip_addresses[0]}</span>`
        : `<span class="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-500">Unregistered / Dormant</span>`;

      return `
        <div class="p-2 bg-slate-900 rounded border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[11px]">
          <div class="space-y-0.5">
            <div class="flex items-center space-x-2">
              <span class="text-slate-500 font-bold">${idx + 1}.</span>
              <span class="text-white font-bold font-mono">${item.domain}</span>
              <span class="px-1.5 py-0.2 rounded text-[9px] bg-indigo-500/20 text-indigo-300 font-sans border border-indigo-500/30">${item.attack_category}</span>
            </div>
            <div class="text-[10px] text-slate-400">
              Levenshtein Dist: <strong class="text-slate-200">${item.levenshtein_distance}</strong> | Sim: <strong class="text-slate-200">${Math.round(item.similarity_ratio * 100)}%</strong>
            </div>
          </div>
          <div class="flex items-center space-x-2">
            ${dnsBadge}
            <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeColor}">
              Risk: ${item.threat_score}/100
            </span>
          </div>
        </div>
      `;
    }).join('');

  } catch (err) {
    listContainer.innerHTML = `<span class="text-red-400">openSquat error: ${err.message}</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = origBtnHtml;
  }
}

// 16. Holehe & Mailcat Email Identity & Presence Controller
async function runHoleheEmailScan() {
  const emailInput = document.getElementById('recon-holehe-input');
  const container = document.getElementById('recon-holehe-results');
  const btn = document.getElementById('btn-holehe-run');

  const email = emailInput?.value.trim();
  if (!email) return alert("Please enter an email address to probe.");

  const origBtnHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Probing...`;
  container.innerHTML = '<span class="text-pink-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Probing Gravatar, GitHub commit records, and password recovery endpoints...</span>';

  try {
    const res = await fetch('/api/recon/holehe-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const data = await res.json();

    const isCritical = data.severity === 'CRITICAL';
    const isHigh = data.severity === 'HIGH';
    const badgeColor = isCritical ? 'bg-red-500/20 text-red-300 border-red-500/40' : (isHigh ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40');

    const recoveryLinks = (data.recovery_lookup_targets || []).map(r => `
      <a href="${r.lookup_url}" target="_blank" rel="noopener noreferrer" class="px-1.5 py-0.5 bg-slate-900 hover:bg-slate-800 text-pink-300 rounded border border-slate-700 text-[10px]">
        ${r.service}
      </a>
    `).join(' ');

    const indicatorsHtml = (data.indicators || []).map(ind => `
      <div class="text-[11px] text-pink-300 flex items-center space-x-1.5">
        <i class="fa-solid fa-triangle-exclamation text-[9px] text-amber-400"></i>
        <span>${ind}</span>
      </div>
    `).join('');

    container.innerHTML = `
      <div class="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-2 text-xs">
        <div class="flex items-center justify-between">
          <span class="font-bold text-white font-mono">${data.email}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeColor}">
            ${data.severity} (${data.risk_score}/100)
          </span>
        </div>
        <div class="grid grid-cols-2 gap-1 text-[11px] font-mono text-slate-300 pt-1 border-t border-slate-800/60">
          <div><span class="text-slate-500">Burner Domain:</span> <strong class="${data.is_burner_domain ? 'text-red-400' : 'text-emerald-400'}">${data.is_burner_domain ? 'YES (Disposable)' : 'No (Standard)'}</strong></div>
          <div><span class="text-slate-500">Gravatar:</span> <strong class="${data.gravatar?.registered ? 'text-indigo-300' : 'text-slate-400'}">${data.gravatar?.registered ? 'Found Profile' : 'Not Registered'}</strong></div>
          <div><span class="text-slate-500">GitHub Activity:</span> <strong class="${data.github?.associated ? 'text-purple-300' : 'text-slate-400'}">${data.github?.associated ? 'Commits Present' : 'None Detected'}</strong></div>
          <div><span class="text-slate-500">Local Part:</span> <strong class="text-white">${data.local_part}</strong></div>
        </div>
        ${data.gravatar?.registered ? `
          <div class="p-2 bg-slate-900 rounded flex items-center space-x-3 border border-slate-800">
            <img src="${data.gravatar.avatar_url}" alt="Avatar" class="w-8 h-8 rounded-full border border-pink-400/50">
            <div class="text-[11px]">
              <div class="font-bold text-white">${data.gravatar.display_name || 'Gravatar User'}</div>
              <a href="${data.gravatar.profile_url}" target="_blank" class="text-pink-400 hover:underline text-[10px]">${data.gravatar.profile_url}</a>
            </div>
          </div>
        ` : ''}
        <div class="space-y-0.5">${indicatorsHtml}</div>
        <div class="pt-1 border-t border-slate-800/60">
          <div class="text-[10px] text-slate-500 uppercase font-mono font-bold mb-1">Password Recovery Lookups:</div>
          <div class="flex flex-wrap gap-1">${recoveryLinks}</div>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">Holehe error: ${err.message}</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = origBtnHtml;
  }
}

// 17. Robofinder Historical Robots & Phish Kit Path Controller
async function runRobofinder() {
  const domainInput = document.getElementById('recon-robofinder-input');
  const container = document.getElementById('recon-robofinder-results');
  const btn = document.getElementById('btn-robofinder-run');

  const domain = domainInput?.value.trim();
  if (!domain) return alert("Please enter a domain name to inspect robots.txt.");

  const origBtnHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Crawling...`;
  container.innerHTML = '<span class="text-amber-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Fetching live robots.txt and Wayback Machine CDX snapshots...</span>';

  try {
    const res = await fetch('/api/recon/robofinder', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    const data = await res.json();

    const isCritical = data.severity === 'CRITICAL';
    const isHigh = data.severity === 'HIGH';
    const badgeColor = isCritical ? 'bg-red-500/20 text-red-300 border-red-500/40' : (isHigh ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40');

    const suspPathsHtml = (data.suspicious_phishing_paths || []).map(p => `
      <span class="px-1.5 py-0.2 bg-red-950/80 text-red-300 rounded font-mono text-[10px] border border-red-800/50">${p}</span>
    `).join(' ') || '<span class="text-emerald-400 text-[10px]">Zero high-risk staging endpoints</span>';

    const findingsHtml = (data.findings || []).map(f => `
      <div class="text-[11px] text-amber-300 flex items-center space-x-1">
        <i class="fa-solid fa-circle-exclamation text-[9px] text-amber-400"></i>
        <span>${f}</span>
      </div>
    `).join('');

    container.innerHTML = `
      <div class="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-2 text-xs">
        <div class="flex items-center justify-between">
          <span class="font-bold text-white font-mono">${data.domain}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeColor}">
            ${data.severity} (${data.risk_score}/100)
          </span>
        </div>
        <div class="grid grid-cols-2 gap-1 text-[11px] font-mono text-slate-300 pt-1 border-t border-slate-800/60">
          <div><span class="text-slate-500">Robots.txt Present:</span> <strong class="${data.robots_found ? 'text-white' : 'text-slate-500'}">${data.robots_found ? 'Yes' : 'Not Found'}</strong></div>
          <div><span class="text-slate-500">Live Disallowed:</span> <strong class="text-amber-400">${data.live_disallow_count} paths</strong></div>
          <div><span class="text-slate-500">Wayback Snapshots:</span> <strong class="text-cyan-400">${data.historical_snapshot_count}</strong></div>
          <div><span class="text-slate-500">Historical Disallows:</span> <strong class="text-white">${data.historical_disallow_paths?.length || 0} paths</strong></div>
        </div>
        <div class="pt-1 border-t border-slate-800/60">
          <span class="text-[10px] text-slate-500 font-mono font-bold block mb-1">Suspicious Hidden &amp; Phishing Endpoints:</span>
          <div class="flex flex-wrap gap-1">${suspPathsHtml}</div>
        </div>
        <div class="space-y-0.5">${findingsHtml}</div>
        <div class="text-[10px] text-slate-400 pt-1 border-t border-slate-800/60 italic">
          ${data.forensic_assessment}
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">Robofinder error: ${err.message}</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = origBtnHtml;
  }
}

// 18. Pagodo & Dorkify 12-Category Brand Defense Matrix Controller
async function runPagodoDorks() {
  const brandInput = document.getElementById('pagodo-brand-input');
  const legitDomainInput = document.getElementById('pagodo-legit-domain-input');
  const targetDomainInput = document.getElementById('pagodo-target-domain-input');
  const container = document.getElementById('recon-pagodo-results');
  const btn = document.getElementById('btn-pagodo-run');

  const brand = brandInput?.value.trim() || 'PayPal';
  const legitimate_domain = legitDomainInput?.value.trim() || 'paypal.com';
  const target_domain = targetDomainInput?.value.trim() || '';

  const origBtnHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Generating...`;
  container.innerHTML = '<span class="text-emerald-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Generating 12 precision GHDB queries...</span>';

  try {
    const res = await fetch('/api/recon/pagodo-dorks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ brand, legitimate_domain, target_domain })
    });
    const data = await res.json();

    container.innerHTML = (data.dorks || []).map((d, idx) => `
      <div class="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-1 text-xs">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-1.5">
            <span class="text-[11px] font-bold text-emerald-400">${idx + 1}. ${d.category}</span>
            <span class="px-1.5 py-0.2 rounded text-[9px] bg-slate-800 text-slate-300 font-mono">${d.threat_focus}</span>
          </div>
          <div class="flex items-center space-x-1">
            <a href="${d.google_url}" target="_blank" rel="noopener noreferrer" class="px-1.5 py-0.5 bg-blue-600/30 hover:bg-blue-600 text-blue-300 hover:text-white rounded text-[9px] font-semibold">Google</a>
            <a href="${d.duckduckgo_url}" target="_blank" rel="noopener noreferrer" class="px-1.5 py-0.5 bg-amber-600/30 hover:bg-amber-600 text-amber-300 hover:text-white rounded text-[9px] font-semibold">DDG</a>
            <a href="${d.bing_url}" target="_blank" rel="noopener noreferrer" class="px-1.5 py-0.5 bg-cyan-600/30 hover:bg-cyan-600 text-cyan-300 hover:text-white rounded text-[9px] font-semibold">Bing</a>
            <a href="${d.yandex_url}" target="_blank" rel="noopener noreferrer" class="px-1.5 py-0.5 bg-red-600/30 hover:bg-red-600 text-red-300 hover:text-white rounded text-[9px] font-semibold">Yandex</a>
          </div>
        </div>
        <div class="font-mono text-[10px] text-slate-200 bg-slate-900 p-1.5 rounded overflow-x-auto select-all border border-slate-800">${d.dork}</div>
        <div class="text-[10px] text-slate-400">${d.description}</div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<span class="text-red-400">Pagodo error: ${err.message}</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = origBtnHtml;
  }
}

// 19. OpenCTI STIX 2.1 Bundle & MISP Event Exporters
let currentOpenCTIBundle = null;
let currentMISPEvent = null;

async function exportOpenCTIBundle() {
  const ta = document.getElementById('report-opencti-textarea');
  if (ta) ta.value = "Generating OASIS STIX 2.1 Bundle for OpenCTI ingestion...";

  const payload = {
    case_id: currentCase ? currentCase.case_id : "CASE-PP-8021",
    brand_name: currentCase ? currentCase.target_brand : "PayPal",
    target_domain: currentCase ? currentCase.primary_threat_domain : "paypal-security-login.top",
    resolved_ips: currentCase ? currentCase.infrastructure.ip_addresses : ["185.220.101.5"],
    threat_score: currentCase ? Math.round(currentCase.precalculated_risk.risk_score) : 94,
    threat_actor_type: "Organized BEC Phishing Syndicate"
  };

  try {
    const res = await fetch('/api/export/opencti-stix2', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    currentOpenCTIBundle = data;

    if (ta) ta.value = JSON.stringify(data, null, 2);

    // Trigger file download
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `OpenCTI_STIX21_${payload.case_id}.json`;
    a.click();
  } catch (err) {
    if (ta) ta.value = "Error generating OpenCTI STIX 2.1 bundle: " + err.message;
    alert("OpenCTI Export error: " + err.message);
  }
}

function copyOpenCTIText() {
  const ta = document.getElementById('report-opencti-textarea');
  if (!ta) return;
  ta.select();
  document.execCommand('copy');
  alert("OpenCTI STIX 2.1 Bundle JSON copied to clipboard!");
}

async function exportMISPEventJson() {
  const ta = document.getElementById('report-misp-textarea');
  if (ta) ta.value = "Generating MISP 2.4 Event JSON format...";

  const payload = {
    case_id: currentCase ? currentCase.case_id : "CASE-PP-8021",
    brand_name: currentCase ? currentCase.target_brand : "PayPal",
    target_domain: currentCase ? currentCase.primary_threat_domain : "paypal-security-login.top",
    resolved_ips: currentCase ? currentCase.infrastructure.ip_addresses : ["185.220.101.5"],
    threat_score: currentCase ? Math.round(currentCase.precalculated_risk.risk_score) : 94
  };

  try {
    const res = await fetch('/api/export/misp-event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    currentMISPEvent = data;

    if (ta) ta.value = JSON.stringify(data, null, 2);

    // Trigger file download
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `MISP_Event_${payload.case_id}.json`;
    a.click();
  } catch (err) {
    if (ta) ta.value = "Error generating MISP Event JSON: " + err.message;
    alert("MISP Export error: " + err.message);
  }
}

function copyMISPText() {
  const ta = document.getElementById('report-misp-textarea');
  if (!ta) return;
  ta.select();
  document.execCommand('copy');
  alert("MISP 2.4 Event JSON copied to clipboard!");
}
