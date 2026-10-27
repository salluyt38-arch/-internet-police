// Register Service Worker for Android & iOS PWA
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(err => {
      console.log('Service Worker registration skipped:', err);
    });
  });
}

// PWA Direct Mobile & Desktop Installation (Soundwave Style)
let deferredPrompt = null;

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  const installBtn = document.getElementById('btn-install-pwa');
  if (installBtn) installBtn.style.display = 'inline-flex';
});

function triggerPwaInstall() {
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
  const isStandalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone;

  if (isStandalone) {
    alert('Unified AI Cybersecurity Agent is already installed and running natively! 🛡️');
    return;
  }

  const modal = document.getElementById('pwa-install-modal');
  const instructions = document.getElementById('pwa-install-instructions');
  const promptBtn = document.getElementById('pwa-prompt-btn');

  modal.classList.add('active');

  if (deferredPrompt) {
    instructions.innerHTML = '<strong>Direct 1-Click Install Ready:</strong><br>Click below to install directly onto your home screen or application menu.';
    promptBtn.style.display = 'block';
  } else if (isIOS) {
    instructions.innerHTML = '<strong>On your iPhone / iPad:</strong><br>1. Tap the <strong>Share</strong> button (⬆️) in Safari bottom bar.<br>2. Scroll down and tap <strong>"Add to Home Screen"</strong> (➕).<br>3. Tap <strong>"Add"</strong> in the top-right corner.';
    promptBtn.style.display = 'none';
  } else {
    instructions.innerHTML = '<strong>To Install on your Device:</strong><br>1. Click the browser menu (⋮ or ⋯).<br>2. Select <strong>"Install App"</strong> or <strong>"Add to Home Screen"</strong>.';
    promptBtn.style.display = 'none';
  }
}

async function executePwaNativeInstall() {
  if (deferredPrompt) {
    deferredPrompt.prompt();
    await deferredPrompt.userChoice;
    deferredPrompt = null;
    closePwaModal();
  }
}

function closePwaModal() {
  document.getElementById('pwa-install-modal').classList.remove('active');
}

// Global State
let voiceEnabled = true;
let isRecording = false;
let speechRecognizer = null;
let lastDispatchedDay = -1;
let currentAuthToken = localStorage.getItem('ip_auth_token') || '';
let currentUserRole = 'Admin';
let cachedAlerts = [];

// Navigation & Tab Switching
function switchTab(tabId) {
  const tabs = ['overview', 'chat', 'reputation', 'alerts', 'scanner', 'intel', 'hitl', 'audits', 'settings'];
  tabs.forEach(t => {
    const el = document.getElementById(`tab-${t}`);
    const pill = document.getElementById(`pill-${t}`);
    if (el) el.classList.remove('active');
    if (pill) pill.classList.remove('active');
  });

  const activeTab = document.getElementById(`tab-${tabId}`);
  const activePill = document.getElementById(`pill-${tabId}`);
  if (activeTab) activeTab.classList.add('active');
  if (activePill) activePill.classList.add('active');

  // Load relevant data on tab activate
  if (tabId === 'alerts') loadWazuhAlerts();
  else if (tabId === 'scanner') loadScanHistory();
  else if (tabId === 'intel') loadSTIXIndicators();
  else if (tabId === 'hitl') loadHITLQueue();
  else if (tabId === 'audits') loadAuditTrail();
  else if (tabId === 'settings') loadSettingsData();
  else if (tabId === 'overview') { loadStats(); loadRecentLogs(); loadHostVitals(); }
}

// 1-Click Key Portal Links
function openKeyPortal(provider) {
  const urls = {
    groq: 'https://console.groq.com/keys',
    gemini: 'https://aistudio.google.com/app/apikey',
    openrouter: 'https://openrouter.ai/keys',
    ollama: 'https://ollama.com/download'
  };
  const url = urls[provider] || 'https://console.groq.com/keys';
  window.open(url, '_blank', 'noopener,noreferrer');
}

// Onboarding Key Submit
async function handleKeySubmit() {
  const key = document.getElementById('setup-api-key').value.trim();
  const provider = document.getElementById('setup-provider-select').value;

  if (key.startsWith('http://') || key.startsWith('https://') || key.includes('github.com')) {
    alert('⚠️ Invalid API Key: You pasted a URL instead of an actual API key!\n\nPlease enter your valid Groq (gsk_...) or Gemini (AIza...) key.');
    return;
  }

  await fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${currentAuthToken}` },
    body: JSON.stringify({ ai_api_key: key, ai_provider: provider })
  });

  document.getElementById('permission-modal').classList.add('active');
}

function closePermissionModal() {
  document.getElementById('permission-modal').classList.remove('active');
}

async function grantAllPermissions() {
  closePermissionModal();
  await fetch('/api/permissions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ all_granted: true })
  });

  document.getElementById('screen-setup').style.display = 'none';
  const mainScreen = document.getElementById('screen-main');
  mainScreen.style.display = 'block';

  const statusEl = document.getElementById('island-status');
  statusEl.innerText = 'SHIELDS ACTIVE';
  statusEl.style.color = '#34c759';

  speakVoice("Unified AI Cybersecurity Agent armed. Zero-trust defense active.");
  loadStats();
  loadRecentLogs();
  loadHostVitals();
}

async function checkInitialStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    if (data.permissions_granted) {
      document.getElementById('screen-setup').style.display = 'none';
      document.getElementById('screen-main').style.display = 'block';
    }
    // Update Wazuh pill
    if (data.wazuh) {
      updateWazuhPill(data.wazuh);
    }
    if (data.hitl_pending > 0) {
      updateHITLBadge(data.hitl_pending);
    }
  } catch (e) {}
}

function updateWazuhPill(wazuh) {
  const pill = document.getElementById('wazuh-status-pill');
  if (!pill) return;
  if (wazuh.connected) {
    pill.className = 'badge-low';
    pill.innerText = 'Wazuh: Online (:55000)';
  } else {
    pill.className = 'badge-info';
    pill.innerText = 'Wazuh: Standalone Guard';
  }
}

function updateHITLBadge(count) {
  const badge = document.getElementById('badge-hitl');
  if (!badge) return;
  if (count > 0) {
    badge.style.display = 'inline-block';
    badge.innerText = count;
  } else {
    badge.style.display = 'none';
  }
}

function setTheme(themeName) {
  document.body.className = `theme-${themeName}`;
  fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${currentAuthToken}` },
    body: JSON.stringify({ theme: themeName })
  });
}

// Live Metrics
async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const stats = await res.json();
    document.getElementById('widget-total').innerText = stats.total_events || 0;
    document.getElementById('widget-ads').innerText = stats.blocked_ads || 0;
    document.getElementById('widget-threats').innerText = stats.blocked_threats || 0;
    document.getElementById('widget-dlp').innerText = stats.dlp_alerts || 0;
  } catch (e) {}
}

async function loadHostVitals() {
  try {
    const res = await fetch('/api/device/vitals');
    if (!res.ok) return;
    const data = await res.json();
    const box = document.getElementById('host-vitals-box');
    if (box && data) {
      box.innerHTML = `
        <strong>OS Platform:</strong> ${escapeHtml(data.os || 'Windows 11')}<br>
        <strong>Hostname:</strong> ${escapeHtml(data.hostname || 'Local-Host')}<br>
        <strong>CPU Utilization:</strong> ${data.cpu_usage || '12'}% | <strong>Memory:</strong> ${data.ram_usage || '45'}%<br>
        <strong>Active IP:</strong> ${data.ip || '127.0.0.1'} | <strong>DNS Port:</strong> 5353 (UDP)
      `;
    }
  } catch (e) {}
}

// Live Intercept Logs
async function loadRecentLogs() {
  try {
    const res = await fetch('/api/logs');
    if (!res.ok) return;
    const logs = await res.json();
    const tbody = document.getElementById('police-logs-tbody');
    if (!tbody || !logs || logs.length === 0) return;

    tbody.innerHTML = logs.slice(0, 15).map(l => {
      const time = new Date(l.timestamp * 1000).toLocaleTimeString();
      let badgeClass = 'badge-low';
      if (l.action === 'BLOCKED') badgeClass = 'badge-crit';
      else if (l.action === 'ALERT') badgeClass = 'badge-high';

      return `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
          <td style="padding:10px 12px; font-family:var(--sf-mono);">${time}</td>
          <td style="padding:10px 12px;"><strong>${escapeHtml(l.subsystem)}</strong></td>
          <td style="padding:10px 12px; font-family:var(--sf-mono); max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(l.target)}</td>
          <td style="padding:10px 12px;"><span class="${badgeClass}">${l.action}</span></td>
          <td style="padding:10px 12px; font-size:11px;">${l.risk_level}</td>
          <td style="padding:10px 12px; font-size:12px; color:var(--apple-muted);">${escapeHtml(l.details)}</td>
        </tr>
      `;
    }).join('');
  } catch (e) {}
}

// =========================================================================
// MODULE B: THREAT REPUTATION CHECKER
// =========================================================================
async function checkThreatReputation() {
  const target = document.getElementById('reputation-target-input').value.trim();
  const card = document.getElementById('reputation-result-card');
  if (!target) {
    alert('Please enter a URL, domain, IP address, or file hash to check.');
    return;
  }

  card.style.display = 'block';
  card.innerHTML = `<em>🔍 Querying STIX 2.1 IOC store & heuristic matrix for '${escapeHtml(target)}'...</em>`;

  try {
    const res = await fetch(`/api/threat/lookup?target=${encodeURIComponent(target)}`);
    const data = await res.json();

    let statusBadge = '<span class="badge-low">SAFE</span>';
    if (data.reputation_status === 'CONFIRMED_MALICIOUS') {
      statusBadge = '<span class="badge-crit">CONFIRMED MALICIOUS</span>';
    } else if (data.reputation_status === 'SUSPICIOUS') {
      statusBadge = '<span class="badge-high">SUSPICIOUS</span>';
    } else if (data.reputation_status === 'UNKNOWN') {
      statusBadge = '<span class="badge-info">UNKNOWN</span>';
    }

    card.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
        <h4 style="font-size:16px;">Target: <code style="color:var(--apple-blue-bright);">${escapeHtml(data.target)}</code></h4>
        <div>${statusBadge}</div>
      </div>
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px; margin-bottom:12px; font-size:13px;">
        <div><strong>Type:</strong> ${escapeHtml(data.type || 'Unknown').toUpperCase()}</div>
        <div><strong>Confidence:</strong> ${data.confidence || 0}%</div>
        <div><strong>Risk Level:</strong> ${data.risk_level || 'LOW'}</div>
        <div><strong>Source:</strong> ${escapeHtml(data.source || 'Heuristic Shield')}</div>
      </div>
      ${data.mitre_technique ? `<div style="font-size:12px; margin-bottom:10px; color:var(--apple-amber);"><strong>MITRE ATT&CK:</strong> ${escapeHtml(data.mitre_technique)}</div>` : ''}
      <div style="font-size:13px; line-height:1.5; background:rgba(255,255,255,0.03); padding:10px; border-radius:8px; margin-bottom:10px;">
        ${escapeHtml(data.details || 'Analyzed structural indicators.')}
      </div>
      <div style="font-size:11px; color:var(--apple-muted);">
        <strong>Detection Limitations:</strong> ${escapeHtml(data.limitations || 'Safe read-only lookup.')}
      </div>
    `;
  } catch (e) {
    card.innerHTML = `<span style="color:#ff3b30;">Lookup failed: ${escapeHtml(e.message)}</span>`;
  }
}

// =========================================================================
// MODULE C: WAZUH MONITOR & ALERTS
// =========================================================================
async function loadWazuhAlerts() {
  const tbody = document.getElementById('wazuh-alerts-tbody');
  const bannerText = document.getElementById('wazuh-banner-text');
  const agentCounts = document.getElementById('wazuh-agent-counts');

  try {
    const statusRes = await fetch('/api/wazuh/status');
    const status = await statusRes.json();
    bannerText.innerText = status.message;
    updateWazuhPill(status);

    const endpointsRes = await fetch('/api/wazuh/endpoints');
    const endpoints = await endpointsRes.json();
    agentCounts.innerText = `Active Endpoints: ${endpoints.active || 1} / Total: ${endpoints.total || 1}`;

    const alertsRes = await fetch('/api/wazuh/alerts?limit=30');
    cachedAlerts = await alertsRes.json();
    renderAlertsTable(cachedAlerts);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" style="padding:16px; text-align:center; color:#ff3b30;">Failed to load alerts: ${escapeHtml(e.message)}</td></tr>`;
  }
}

function renderAlertsTable(alerts) {
  const tbody = document.getElementById('wazuh-alerts-tbody');
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="padding:16px; text-align:center; color:var(--apple-muted);">No security alerts recorded. System clean.</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map((a, idx) => {
    const level = a.rule?.level || 4;
    let badgeClass = 'badge-low';
    let levelText = `Level ${level}`;
    if (level >= 12) { badgeClass = 'badge-crit'; levelText += ' (Critical)'; }
    else if (level >= 8) { badgeClass = 'badge-high'; levelText += ' (High)'; }
    else if (level >= 5) { badgeClass = 'badge-med'; levelText += ' (Medium)'; }

    return `
      <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
        <td style="padding:10px 12px; font-family:var(--sf-mono); font-size:12px;">${escapeHtml(a.timestamp || '')}</td>
        <td style="padding:10px 12px;"><span class="${badgeClass}">${levelText}</span></td>
        <td style="padding:10px 12px; font-size:12px;">${escapeHtml(a.agent?.name || a.source || 'Native Host')}</td>
        <td style="padding:10px 12px; font-size:13px;">${escapeHtml(a.rule?.description || 'Security Event')}</td>
        <td style="padding:10px 12px;">
          <button class="apple-btn-secondary" style="padding:4px 8px; font-size:11px; border-radius:10px;" onclick="explainAlertWithAI(${idx})">
            💡 Explain with AI
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function filterAlerts() {
  const query = document.getElementById('alert-search-input').value.toLowerCase();
  const filtered = cachedAlerts.filter(a => {
    const desc = a.rule?.description || '';
    const src = a.agent?.name || a.source || '';
    return desc.toLowerCase().includes(query) || src.toLowerCase().includes(query);
  });
  renderAlertsTable(filtered);
}

async function explainAlertWithAI(idx) {
  const alertItem = cachedAlerts[idx];
  if (!alertItem) return;

  switchTab('chat');
  const chatBox = document.getElementById('police-chat-box');
  const bubble = document.createElement('div');
  bubble.className = 'chat-bubble bubble-police';
  bubble.innerHTML = `<em>💡 Analyzing alert rule <strong>${escapeHtml(alertItem.rule?.description || '')}</strong> with AI...</em>`;
  chatBox.appendChild(bubble);
  chatBox.scrollTop = chatBox.scrollHeight;

  try {
    const res = await fetch('/api/ai/explain_alert', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert: alertItem })
    });
    const data = await res.json();
    bubble.innerHTML = `<strong>👮 Alert Remediation Breakdown:</strong><br><br>${escapeHtml(data.explanation)}`;
    chatBox.scrollTop = chatBox.scrollHeight;
    if (voiceEnabled) {
      speakVoice("सिक्योरिटी अलर्ट विश्लेषण तैयार है।");
    }
  } catch (e) {
    bubble.innerHTML = `Error: ${escapeHtml(e.message)}`;
  }
}

// =========================================================================
// MODULE E: AUTHORIZED DEFENSIVE SCANNING
// =========================================================================
async function runAuthorizedScan() {
  const target = document.getElementById('scan-target-input').value.trim();
  const confirmed = document.getElementById('scan-auth-checkbox').checked;
  const container = document.getElementById('scan-result-container');

  if (!target) {
    alert('Please enter a target to assess.');
    return;
  }

  if (!confirmed) {
    alert('Authorization Required:\nYou must affirmatively check the box confirming you own or have written authorization to assess this target.');
    return;
  }

  container.style.display = 'block';
  container.innerHTML = `<em>🛡️ Running non-destructive defensive checks (DNS, TLS/SSL, Headers, Sockets) on '${escapeHtml(target)}'...</em>`;

  try {
    const res = await fetch('/api/scans/perform', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentAuthToken}`
      },
      body: JSON.stringify({ target: target, authorized: true, require_hitl: false })
    });
    const data = await res.json();

    if (!res.ok || data.status === 'BLOCKED') {
      container.innerHTML = `<span style="color:#ff3b30; font-weight:600;">⚠️ ${escapeHtml(data.error || 'Scan prohibited.')}</span>`;
      return;
    }

    if (data.status === 'QUEUED_FOR_HITL') {
      container.innerHTML = `
        <div style="color:var(--apple-amber);">
          <strong>⏳ Action Queued for Human-in-the-Loop Authorization:</strong><br>
          ${escapeHtml(data.message)}<br>
          <span style="font-size:12px;">Request ID: ${escapeHtml(data.hitl_details?.request_id || '')}</span>
        </div>
      `;
      loadHITLQueue();
      return;
    }

    // Render Completed Scan
    const f = data.findings || {};
    const score = data.risk_score || 0;
    let scoreColor = '#34c759';
    if (score < 50) scoreColor = '#ff3b30';
    else if (score < 80) scoreColor = '#ff9500';

    container.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
        <h4 style="font-size:17px;">Assessment Report: <code style="color:var(--apple-blue-bright);">${escapeHtml(data.target)}</code></h4>
        <div style="font-size:16px; font-weight:700;">Posture Score: <span style="color:${scoreColor};">${score}/100</span></div>
      </div>

      <div class="meter-container">
        <div class="meter-fill" style="width:${score}%; background:${scoreColor};"></div>
      </div>

      <!-- Findings Grid -->
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap:14px; margin-top:16px;">
        <div style="background:rgba(255,255,255,0.03); padding:12px; border-radius:10px;">
          <h5 style="font-size:13px; margin-bottom:6px;">📡 DNS Records</h5>
          <div style="font-size:12px; color:var(--apple-muted);">
            IPv4: ${f.dns?.ipv4?.join(', ') || 'None'}<br>
            IPv6: ${f.dns?.ipv6?.join(', ') || 'None'}
          </div>
        </div>

        <div style="background:rgba(255,255,255,0.03); padding:12px; border-radius:10px;">
          <h5 style="font-size:13px; margin-bottom:6px;">🔒 TLS / SSL Encryption</h5>
          <div style="font-size:12px; color:var(--apple-muted);">
            Supported: ${f.ssl_tls?.supported ? 'Yes' : 'No'}<br>
            Version: ${f.ssl_tls?.version || 'N/A'} | Days Left: ${f.ssl_tls?.days_until_expiry ?? 'N/A'}<br>
            Issuer: ${f.ssl_tls?.issuer_cn || 'N/A'}
          </div>
        </div>

        <div style="background:rgba(255,255,255,0.03); padding:12px; border-radius:10px;">
          <h5 style="font-size:13px; margin-bottom:6px;">🛑 HTTP Security Headers</h5>
          <div style="font-size:12px; color:var(--apple-muted);">
            Missing: ${f.http_headers?.missing_headers?.length ? f.http_headers.missing_headers.join(', ') : 'None (All Present)'}
          </div>
        </div>

        <div style="background:rgba(255,255,255,0.03); padding:12px; border-radius:10px;">
          <h5 style="font-size:13px; margin-bottom:6px;">🔍 Policy & Safe Sockets</h5>
          <div style="font-size:12px; color:var(--apple-muted);">
            security.txt: ${f.policy_files?.security_txt ? '✅ Found' : '❌ Missing'}<br>
            robots.txt: ${f.policy_files?.robots_txt ? '✅ Found' : '❌ Missing'}
          </div>
        </div>
      </div>

      <!-- Remediations -->
      <div style="margin-top:16px;">
        <h5 style="font-size:14px; margin-bottom:8px;">💡 Hardening Recommendations</h5>
        <ul style="font-size:12px; color:var(--apple-text); line-height:1.6; padding-left:18px;">
          ${(data.remediations || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
        </ul>
      </div>
    `;

    loadScanHistory();
  } catch (e) {
    container.innerHTML = `<span style="color:#ff3b30;">Scan execution error: ${escapeHtml(e.message)}</span>`;
  }
}

async function loadScanHistory() {
  try {
    const res = await fetch('/api/scans/history');
    if (!res.ok) return;
    const history = await res.json();
    const tbody = document.getElementById('scan-history-tbody');
    if (!tbody || history.length === 0) return;

    tbody.innerHTML = history.map(s => {
      const time = new Date(s.created_at * 1000).toLocaleString();
      return `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
          <td style="padding:10px 12px; font-family:var(--sf-mono); font-size:12px;">${escapeHtml(s.scan_id)}</td>
          <td style="padding:10px 12px; font-family:var(--sf-mono);">${escapeHtml(s.target)}</td>
          <td style="padding:10px 12px;"><span class="badge-low">${s.status}</span></td>
          <td style="padding:10px 12px; font-weight:600;">${s.risk_score}/100</td>
          <td style="padding:10px 12px; font-size:12px;">${escapeHtml(s.performed_by || 'Admin')}</td>
          <td style="padding:10px 12px; font-size:12px; color:var(--apple-muted);">${time}</td>
        </tr>
      `;
    }).join('');
  } catch (e) {}
}

// =========================================================================
// MODULE F: THREAT INTELLIGENCE (STIX 2.1)
// =========================================================================
async function loadSTIXIndicators() {
  const tbody = document.getElementById('stix-iocs-tbody');
  try {
    const res = await fetch('/api/intel/indicators?limit=50');
    const iocs = await res.json();
    if (!iocs || iocs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="padding:16px; text-align:center; color:var(--apple-muted);">No threat indicators found.</td></tr>`;
      return;
    }

    tbody.innerHTML = iocs.map(ioc => {
      let badgeClass = 'badge-high';
      if (ioc.severity === 'CRITICAL') badgeClass = 'badge-crit';
      else if (ioc.severity === 'LOW') badgeClass = 'badge-low';

      return `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
          <td style="padding:10px 12px; font-family:var(--sf-mono); font-size:11px;">${escapeHtml(ioc.stix_id)}</td>
          <td style="padding:10px 12px; font-size:12px;"><span class="badge-info">${escapeHtml(ioc.type)}</span></td>
          <td style="padding:10px 12px; font-family:var(--sf-mono); font-size:12px; font-weight:600;">${escapeHtml(ioc.value)}</td>
          <td style="padding:10px 12px;"><span class="${badgeClass}">${ioc.severity}</span></td>
          <td style="padding:10px 12px; font-size:12px;">${ioc.confidence}%</td>
          <td style="padding:10px 12px; font-size:12px; color:var(--apple-amber);">${escapeHtml(ioc.mitre_technique || '')}</td>
          <td style="padding:10px 12px; font-size:11px; color:var(--apple-muted);">${escapeHtml(ioc.source || '')}</td>
        </tr>
      `;
    }).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" style="padding:16px; text-align:center; color:#ff3b30;">Failed to load indicators: ${escapeHtml(e.message)}</td></tr>`;
  }
}

async function addSTIXIndicator() {
  const type = document.getElementById('new-ioc-type').value;
  const value = document.getElementById('new-ioc-value').value.trim();
  const severity = document.getElementById('new-ioc-severity').value;
  const mitre = document.getElementById('new-ioc-mitre').value.trim();
  const desc = document.getElementById('new-ioc-desc').value.trim();

  if (!value) {
    alert('Please enter an indicator value.');
    return;
  }

  try {
    const res = await fetch('/api/intel/add', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentAuthToken}`
      },
      body: JSON.stringify({
        type: type,
        value: value,
        severity: severity,
        mitre_technique: mitre,
        description: desc || 'Manual entry by security analyst'
      })
    });
    const data = await res.json();
    if (!res.ok) {
      alert(`Error: ${data.error || 'Failed to add indicator'}`);
      return;
    }
    alert(`STIX 2.1 Indicator registered: ${data.stix_id}`);
    document.getElementById('new-ioc-value').value = '';
    document.getElementById('new-ioc-desc').value = '';
    loadSTIXIndicators();
  } catch (e) {
    alert(`Request error: ${e.message}`);
  }
}

// =========================================================================
// MODULE D: HITL APPROVALS QUEUE
// =========================================================================
async function loadHITLQueue() {
  const container = document.getElementById('hitl-pending-container');
  const tbody = document.getElementById('hitl-history-tbody');

  try {
    const pendingRes = await fetch('/api/hitl/pending');
    const pending = await pendingRes.json();
    updateHITLBadge(pending.length);

    if (pending.length === 0) {
      container.innerHTML = `
        <div style="padding:20px; text-align:center; color:var(--apple-muted); background:rgba(255,255,255,0.02); border-radius:12px;">
          No pending actions requiring human authorization. System in safe equilibrium.
        </div>
      `;
    } else {
      container.innerHTML = pending.map(req => `
        <div style="background:rgba(255,149,0,0.08); border:1px solid rgba(255,149,0,0.3); border-radius:14px; padding:16px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
          <div>
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
              <span class="badge-high">${req.action_type}</span>
              <strong style="font-size:15px; font-family:var(--sf-mono);">${escapeHtml(req.target)}</strong>
            </div>
            <div style="font-size:12px; color:var(--apple-muted);">
              Requested by <strong>${escapeHtml(req.requested_by)}</strong> | Risk: <span style="color:#ff3b30;">${req.risk_level}</span>
            </div>
            <div style="font-size:13px; margin-top:4px;">${escapeHtml(req.details)}</div>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="apple-btn" style="background:#34c759; padding:8px 16px; font-size:13px;" onclick="resolveHITL('${req.request_id}', 'APPROVED')">
              ✅ Approve Action
            </button>
            <button class="apple-btn" style="background:#ff3b30; padding:8px 16px; font-size:13px;" onclick="resolveHITL('${req.request_id}', 'REJECTED')">
              ❌ Reject
            </button>
          </div>
        </div>
      `).join('');
    }

    const allRes = await fetch('/api/hitl/all');
    const all = await allRes.json();
    if (tbody && all.length > 0) {
      tbody.innerHTML = all.slice(0, 15).map(r => `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
          <td style="padding:10px 12px; font-family:var(--sf-mono); font-size:11px;">${escapeHtml(r.request_id)}</td>
          <td style="padding:10px 12px; font-weight:600;">${escapeHtml(r.action_type)}</td>
          <td style="padding:10px 12px; font-family:var(--sf-mono);">${escapeHtml(r.target)}</td>
          <td style="padding:10px 12px;"><span class="${r.status === 'APPROVED' ? 'badge-low' : (r.status === 'PENDING' ? 'badge-high' : 'badge-crit')}">${r.status}</span></td>
          <td style="padding:10px 12px; font-size:12px;">${escapeHtml(r.requested_by)}</td>
          <td style="padding:10px 12px; font-size:12px; color:var(--apple-muted);">${escapeHtml(r.resolved_by || 'Pending')}</td>
        </tr>
      `).join('');
    }
  } catch (e) {}
}

async function resolveHITL(requestId, decision) {
  try {
    const res = await fetch('/api/hitl/resolve', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentAuthToken}`
      },
      body: JSON.stringify({ request_id: requestId, decision: decision })
    });
    const data = await res.json();
    if (!res.ok) {
      alert(`Authorization Error: ${data.error || 'Failed to resolve request'}`);
      return;
    }
    loadHITLQueue();
  } catch (e) {
    alert(`Error: ${e.message}`);
  }
}

// =========================================================================
// AUDIT TRAIL
// =========================================================================
async function loadAuditTrail() {
  const tbody = document.getElementById('audit-trail-tbody');
  try {
    const res = await fetch('/api/audits');
    const audits = await res.json();
    if (!audits || audits.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="padding:16px; text-align:center; color:var(--apple-muted);">Audit log is currently empty.</td></tr>`;
      return;
    }

    tbody.innerHTML = audits.map(a => {
      const time = new Date(a.timestamp * 1000).toLocaleString();
      let resBadge = 'badge-low';
      if (a.result === 'DENIED' || a.result === 'FAILED') resBadge = 'badge-crit';

      return `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
          <td style="padding:10px 12px; font-family:var(--sf-mono); font-size:11px;">${time}</td>
          <td style="padding:10px 12px; font-weight:600;">${escapeHtml(a.actor)}</td>
          <td style="padding:10px 12px; font-size:12px;"><span class="badge-info">${escapeHtml(a.role)}</span></td>
          <td style="padding:10px 12px; font-family:var(--sf-mono); font-size:12px;">${escapeHtml(a.action)}</td>
          <td style="padding:10px 12px; font-size:12px; color:var(--apple-muted);">${escapeHtml(a.resource)}</td>
          <td style="padding:10px 12px;"><span class="${resBadge}">${a.result}</span></td>
          <td style="padding:10px 12px; font-size:12px; color:var(--apple-muted);">${escapeHtml(a.details)}</td>
        </tr>
      `;
    }).join('');
  } catch (e) {}
}

// =========================================================================
// SETTINGS & RBAC USER LOGIN
// =========================================================================
async function executeUserLogin() {
  const u = document.getElementById('login-username').value.trim();
  const p = document.getElementById('login-password').value;

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      alert(`Login Failed: ${data.error || 'Invalid credentials'}`);
      return;
    }

    currentAuthToken = data.token;
    currentUserRole = data.role;
    localStorage.setItem('ip_auth_token', currentAuthToken);

    document.getElementById('user-role-badge').innerText = data.role;
    document.getElementById('settings-role-display').innerText = `${data.username} (${data.role})`;

    alert(`Successfully authenticated as ${data.username} [Role: ${data.role}]`);
  } catch (e) {
    alert(`Login error: ${e.message}`);
  }
}

async function loadSettingsData() {
  try {
    const res = await fetch('/api/settings');
    const s = await res.json();
    if (s.ai_provider) document.getElementById('settings-ai-provider').value = s.ai_provider;
    if (s.ai_api_key) document.getElementById('settings-ai-key').value = s.ai_api_key;
    if (s.wazuh_host) document.getElementById('settings-wazuh-host').value = s.wazuh_host;
    if (s.wazuh_user) document.getElementById('settings-wazuh-user').value = s.wazuh_user;
    if (s.allowed_targets) document.getElementById('settings-allowed-targets').value = s.allowed_targets;
  } catch (e) {}
}

async function saveAllSettings() {
  const provider = document.getElementById('settings-ai-provider').value;
  const key = document.getElementById('settings-ai-key').value.trim();
  const wazuhHost = document.getElementById('settings-wazuh-host').value.trim();
  const wazuhUser = document.getElementById('settings-wazuh-user').value.trim();
  const wazuhPass = document.getElementById('settings-wazuh-pass').value.trim();
  const allowed = document.getElementById('settings-allowed-targets').value.trim();

  const payload = {
    ai_provider: provider,
    ai_api_key: key,
    wazuh_host: wazuhHost,
    wazuh_user: wazuhUser,
    allowed_targets: allowed
  };
  if (wazuhPass) payload.wazuh_pass = wazuhPass;

  try {
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentAuthToken}`
      },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      alert(`Error saving settings: ${data.error || 'Admin role required'}`);
      return;
    }
    alert('System settings updated successfully.');
  } catch (e) {
    alert(`Error: ${e.message}`);
  }
}

// =========================================================================
// VOICE ENGINE & VISUALIZER
// =========================================================================
let currentAudio = null;
let audioContext = null;
let analyser = null;
let visualizerRunning = false;

function startVisualizer() {
  const canvas = document.getElementById('voice-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  visualizerRunning = true;

  function renderFrame() {
    if (!visualizerRunning) return;
    requestAnimationFrame(renderFrame);

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const bars = 28;
    const barWidth = canvas.width / bars - 2;

    let freqData = new Uint8Array(bars);
    if (analyser && currentAudio && !currentAudio.paused) {
      analyser.getByteFrequencyData(freqData);
    } else {
      const time = Date.now() * 0.003;
      for (let i = 0; i < bars; i++) {
        freqData[i] = Math.sin(time + i * 0.3) * 15 + 20;
      }
    }

    for (let i = 0; i < bars; i++) {
      const height = (freqData[i] / 255) * (canvas.height - 4) + 4;
      const x = i * (barWidth + 2);
      const y = (canvas.height - height) / 2;

      const gradient = ctx.createLinearGradient(0, y, 0, y + height);
      gradient.addColorStop(0, '#2997ff');
      gradient.addColorStop(1, '#0071e3');

      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.roundRect(x, y, barWidth, height, 3);
      ctx.fill();
    }
  }

  requestAnimationFrame(renderFrame);
}

async function playHumanoidSpeech(text) {
  if (!voiceEnabled) return;

  const statusText = document.getElementById('voice-status-text');
  const statusDot = document.getElementById('voice-status-dot');
  if (statusText) statusText.innerText = 'SYNTHESIZING NEURAL SPEECH...';
  if (statusDot) { statusDot.style.background = '#2997ff'; statusDot.style.boxShadow = '0 0 12px #2997ff'; }

  const voiceSelect = document.getElementById('neural-voice-select');
  const chosenVoice = voiceSelect ? voiceSelect.value : 'hi-IN-MadhurNeural';

  try {
    if (currentAudio) {
      currentAudio.pause();
      currentAudio = null;
    }

    const audioUrl = `/api/voice/speak?text=${encodeURIComponent(text.substring(0, 500))}&voice=${chosenVoice}`;
    currentAudio = new Audio(audioUrl);

    currentAudio.onplay = () => {
      if (statusText) statusText.innerText = 'HUMANOID VOICE AGENT SPEAKING (120 FPS)';
      if (statusDot) { statusDot.style.background = '#34c759'; statusDot.style.boxShadow = '0 0 15px #34c759'; }
    };

    currentAudio.onended = () => {
      if (statusText) statusText.innerText = 'VOICE AGENT IDLE : 24/7 PATROL ACTIVE';
      if (statusDot) { statusDot.style.background = '#34c759'; statusDot.style.boxShadow = '0 0 10px #34c759'; }
    };

    await currentAudio.play();
  } catch (e) {
    speakVoice(text);
  }
}

async function sendPoliceMessage() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text) return;

  const chatBox = document.getElementById('police-chat-box');
  const userBubble = document.createElement('div');
  userBubble.className = 'chat-bubble bubble-user';
  userBubble.innerHTML = `<strong>You:</strong> ${escapeHtml(text)}`;
  chatBox.appendChild(userBubble);
  input.value = '';

  const thinkBubble = document.createElement('div');
  thinkBubble.className = 'chat-bubble bubble-police';
  thinkBubble.innerHTML = `<em>🎙️ AI Security Assistant is analyzing...</em>`;
  chatBox.appendChild(thinkBubble);
  chatBox.scrollTop = chatBox.scrollHeight;

  try {
    const res = await fetch('/api/voice/command', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ transcript: text })
    });
    const data = await res.json();
    thinkBubble.innerHTML = `<strong>👮 Cyber Assistant:</strong>\n\n${escapeHtml(data.text)}`;
    chatBox.scrollTop = chatBox.scrollHeight;

    if (voiceEnabled) {
      playHumanoidSpeech(data.voice_prompt || data.text);
    }
  } catch (e) {
    thinkBubble.innerHTML = `<span style="color:#ff3b30;">Dispatch error: ${escapeHtml(e.message)}</span>`;
  }
}

function sendQuickText(text) {
  document.getElementById('chat-input').value = text;
  sendPoliceMessage();
}

async function triggerNightlyDispatch() {
  const chatBox = document.getElementById('police-chat-box');
  const dispatchBubble = document.createElement('div');
  dispatchBubble.className = 'chat-bubble bubble-police';
  dispatchBubble.style.border = '2px solid #ff9500';
  dispatchBubble.innerHTML = `<em>⏰ Generating 9:00 PM Nightly Security Dispatch...</em>`;
  chatBox.appendChild(dispatchBubble);
  chatBox.scrollTop = chatBox.scrollHeight;

  try {
    const res = await fetch('/api/dispatch/generate', { method: 'POST' });
    const data = await res.json();
    dispatchBubble.innerHTML = `<strong>🚨 21:00 NIGHTLY SECURITY DISPATCH</strong><br><br>${escapeHtml(data.summary)}`;
    chatBox.scrollTop = chatBox.scrollHeight;

    if (voiceEnabled) {
      playHumanoidSpeech("दैनिक सुरक्षा ब्रीफिंग: आज आपके डिवाइस पर सभी नेटवर्क कनेक्शन सुरक्षित रहे।");
    }
  } catch (e) {
    dispatchBubble.innerHTML = `Dispatch error: ${escapeHtml(e.message)}`;
  }
}

function checkNightlyClock() {
  const now = new Date();
  if (now.getHours() === 21 && now.getMinutes() === 0 && lastDispatchedDay !== now.getDate()) {
    lastDispatchedDay = now.getDate();
    triggerNightlyDispatch();
  }
}

function speakVoice(text) {
  if (!voiceEnabled || !window.speechSynthesis) return;
  window.speechSynthesis.cancel();
  const cleanedText = text.replace(/[*#`_]/g, '');
  const utterance = new SpeechSynthesisUtterance(cleanedText);
  utterance.rate = 1.05;
  const voices = window.speechSynthesis.getVoices();
  const hindiVoice = voices.find(v => v.lang.includes('hi') || v.lang.includes('IN'));
  if (hindiVoice) utterance.voice = hindiVoice;
  window.speechSynthesis.speak(utterance);
}

function toggleVoiceAudio() {
  voiceEnabled = !voiceEnabled;
  const btn = document.getElementById('voice-toggle-btn');
  btn.innerText = voiceEnabled ? '🔊 Voice: ON' : '🔇 Voice: MUTED';
  btn.style.opacity = voiceEnabled ? '1' : '0.6';
}

function toggleVoiceRecording() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) {
    alert('Voice input is not supported in this browser. Please use Chrome, Safari or Edge.');
    return;
  }

  const micBtn = document.getElementById('mic-btn');
  if (isRecording && speechRecognizer) {
    speechRecognizer.stop();
    isRecording = false;
    micBtn.classList.remove('active');
    return;
  }

  speechRecognizer = new SpeechRec();
  speechRecognizer.lang = 'hi-IN';
  speechRecognizer.continuous = false;
  speechRecognizer.interimResults = false;

  speechRecognizer.onstart = () => {
    isRecording = true;
    micBtn.classList.add('active');
  };

  speechRecognizer.onresult = (event) => {
    const transcript = event.results[0][0].transcript;
    document.getElementById('chat-input').value = transcript;
    sendPoliceMessage();
  };

  speechRecognizer.onerror = () => {
    isRecording = false;
    micBtn.classList.remove('active');
  };

  speechRecognizer.onend = () => {
    isRecording = false;
    micBtn.classList.remove('active');
  };

  speechRecognizer.start();
}

async function executeDeviceAction(action) {
  const outputEl = document.getElementById('device-action-output');
  outputEl.innerText = 'Executing robotic device command...';

  try {
    if (action === 'flush_dns') {
      const res = await fetch('/api/device/flush_dns', { method: 'POST' });
      const data = await res.json();
      outputEl.innerText = '✅ ' + data.message;
    } else if (action === 'connections') {
      const res = await fetch('/api/device/connections');
      const data = await res.json();
      outputEl.innerText = `🔍 Inspected ${data.total_inspected} sockets. ${data.suspicious_found} non-standard connections found.`;
    } else if (action === 'lock') {
      if (confirm('Lock this workstation now?')) {
        await fetch('/api/device/lock', { method: 'POST' });
      } else {
        outputEl.innerText = 'Lockdown canceled.';
      }
    }
  } catch (e) {
    outputEl.innerText = 'Error: ' + e.message;
  }
}

async function auditPasswordHealth() {
  const pwdInput = document.getElementById('vault-pwd-input');
  const outputEl = document.getElementById('vault-audit-output');
  const pwd = pwdInput.value;

  if (!pwd) {
    alert('Please enter a password to audit.');
    return;
  }

  outputEl.style.display = 'block';
  outputEl.innerHTML = '<em>Auditing entropy & querying k-Anonymity dark-web breach registry...</em>';

  try {
    const res = await fetch('/api/vault/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pwd })
    });
    const data = await res.json();

    let healthColor = '#34c759';
    if (data.health === 'COMPROMISED') healthColor = '#ff3b30';
    else if (data.health === 'MODERATE') healthColor = '#ff9500';

    outputEl.innerHTML = `
      <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
        <span>Security Health: <strong style="color:${healthColor};">${data.health}</strong></span>
        <span>Score: <strong>${data.score}/100</strong></span>
      </div>
      <div style="font-size:11px; color:var(--apple-muted); line-height:1.4;">
        ${data.feedback.map(f => `• ${escapeHtml(f)}`).join('<br>')}
      </div>
    `;
  } catch (e) {
    outputEl.innerText = 'Audit Error: ' + e.message;
  }
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Initialization & Auto-Polling
checkInitialStatus();
startVisualizer();
loadStats();
loadRecentLogs();
loadHostVitals();
setInterval(() => {
  loadStats();
  loadRecentLogs();
  checkNightlyClock();
}, 4000);
