/**
 * ScamLens Content Script (content.js)
 *
 * Features:
 * 1. Page signal collection (forms, keywords) → background rules engine
 * 2. In-page Dangerous site warning banner (Shadow DOM)
 * 3. Link Hover Preview — threat score tooltip on any <a> tag
 * 4. Dark Pattern Detector — flags fake urgency, countdowns, scarcity
 * 5. Notification Permission Blocker — auto-denies on suspicious sites
 */

// ── Urgency / Phishing Phrases ──
const URGENCY_PATTERNS = [
  /\bverify\s+(your\s+)?account\b/i,
  /\burgent\s+action\b/i,
  /\bimmediate\s+action\b/i,
  /\baccount\s+(suspended|blocked|locked|terminated)\b/i,
  /\bsecurity\s+alert\b/i,
  /\bunauthorized\s+access\b/i,
  /\bone-time\s+password\b/i,
  /\botp\s*(verification|required)?\b/i,
  /\benter\s+otp\b/i,
  /\bpayment\s+failed\b/i,
  /\bupdate\s+billing\b/i,
  /\bconfirm\s+identity\b/i,
  /\bkyc\s+update\b/i,
  /\bpan\s+verification\b/i,
  /\baadhaar\s+verify\b/i,
  /\bclaim\s+reward\b/i,
  /\blimited\s+time\b/i
];

// ── Dark Pattern Phrases ──
const DARK_PATTERNS = [
  { pattern: /\b(only\s+\d+\s+left|limited\s+stock|selling\s+fast)\b/i,     label: 'Fake Scarcity',    icon: '⚠️' },
  { pattern: /\b(offer\s+expires|deal\s+ends|time\s+running\s+out)\b/i,     label: 'False Urgency',    icon: '⏰' },
  { pattern: /\b(you('ve|\s+have)\s+won|congratulations.*prize|selected.*winner)\b/i, label: 'Lottery Scam', icon: '🎰' },
  { pattern: /\b(free\s+gift|claim\s+now|act\s+now|don't\s+miss)\b/i,       label: 'Pressure Tactic',  icon: '🚩' },
  { pattern: /\b(your\s+(device|pc|computer)\s+is\s+(infected|virus|at\s+risk))\b/i, label: 'Tech Support Scam', icon: '💀' },
  { pattern: /\b(wire\s+transfer|western\s+union|gift\s+card.*payment)\b/i,  label: 'Payment Scam',     icon: '💸' },
];

// ─────────────────────────────────────────────
// 1. Form Signal Collection
// ─────────────────────────────────────────────
function collectFormSignals() {
  const forms = document.querySelectorAll('form');
  let passwordForm = false;
  let formTargetHost = null;

  for (const form of forms) {
    const hasPassword = form.querySelector('input[type="password"]');
    const hasPayment  = form.querySelector('input[name*="card" i], input[name*="cvv" i], input[autocomplete*="cc-" i]');

    if (hasPassword || hasPayment) {
      passwordForm = true;
      try {
        const rawAction   = form.getAttribute('action') || window.location.href;
        const resolvedUrl = new URL(rawAction, window.location.href);
        formTargetHost    = resolvedUrl.hostname.toLowerCase();
      } catch (e) {
        formTargetHost = window.location.hostname.toLowerCase();
      }
      break;
    }
  }

  if (!passwordForm) {
    const loosePassword = document.querySelector('input[type="password"]');
    if (loosePassword) {
      passwordForm = true;
      formTargetHost = window.location.hostname.toLowerCase();
    }
  }

  return { passwordForm, formTargetHost };
}

function collectKeywordSignals() {
  const bodyText = (document.body ? document.body.innerText : '') || '';
  const sample   = bodyText.slice(0, 40000);
  const hits     = [];
  for (const pattern of URGENCY_PATTERNS) {
    const match = sample.match(pattern);
    if (match) hits.push(match[0].toLowerCase());
  }
  return [...new Set(hits)];
}

function sendPageSignals() {
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) return;
  try {
    chrome.runtime.sendMessage({
      type: 'PAGE_SIGNALS',
      url: window.location.href,
      pageSignals: {
        passwordForm:   collectFormSignals().passwordForm,
        formTargetHost: collectFormSignals().formTargetHost,
        keywordHits:    collectKeywordSignals()
      }
    });
  } catch (err) {}
}

// ─────────────────────────────────────────────
// 2. In-page Danger Banner (Shadow DOM)
// ─────────────────────────────────────────────
function showDangerousWarning(analysis) {
  if (document.getElementById('scamlens-warning-container')) return;

  const container = document.createElement('div');
  container.id = 'scamlens-warning-container';
  const shadow = container.attachShadow({ mode: 'closed' });

  const style = document.createElement('style');
  style.textContent = `
    .sl-banner {
      position: fixed; top: 16px; right: 16px; max-width: 420px;
      background: #180909; color: #fff;
      border: 1px solid #ef4444; border-radius: 12px; padding: 16px;
      box-shadow: 0 12px 36px rgba(0,0,0,0.7), 0 0 20px rgba(239,68,68,0.25);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 13px; line-height: 1.5; z-index: 2147483647;
      animation: slSlideDown 0.3s cubic-bezier(0.16,1,0.3,1);
    }
    @keyframes slSlideDown { from{transform:translateY(-20px);opacity:0} to{transform:translateY(0);opacity:1} }
    .sl-header { display:flex; align-items:center; gap:8px; margin-bottom:8px; }
    .sl-badge  { background:#ef4444; color:#fff; font-size:11px; font-weight:800; padding:3px 8px; border-radius:6px; text-transform:uppercase; }
    .sl-title  { font-weight:700; font-size:14px; color:#fca5a5; }
    .sl-close  { margin-left:auto; background:transparent; border:none; color:#9ca3af; font-size:18px; cursor:pointer; padding:4px 8px; border-radius:4px; }
    .sl-close:hover { color:#fff; background:rgba(255,255,255,0.1); }
    .sl-body   { color:#e5e7eb; margin-bottom:12px; font-size:12.5px; }
    .sl-evidence { background:rgba(255,255,255,0.05); border-left:3px solid #ef4444; padding:6px 10px; border-radius:4px; font-size:11.5px; color:#fecaca; margin-bottom:12px; }
    .sl-actions  { display:flex; gap:8px; }
    .sl-btn-leave   { flex:1; background:#ef4444; color:#fff; border:none; border-radius:6px; padding:8px 12px; font-weight:700; font-size:12px; cursor:pointer; }
    .sl-btn-dismiss { background:rgba(255,255,255,0.1); color:#d1d5db; border:1px solid rgba(255,255,255,0.15); border-radius:6px; padding:8px 12px; font-weight:600; font-size:12px; cursor:pointer; }
  `;
  shadow.appendChild(style);

  const banner = document.createElement('div');
  banner.className = 'sl-banner';
  banner.setAttribute('role', 'alert');

  const header   = document.createElement('div');  header.className = 'sl-header';
  const badge    = document.createElement('span'); badge.className  = 'sl-badge'; badge.textContent = 'DANGEROUS';
  const title    = document.createElement('span'); title.className  = 'sl-title'; title.textContent = 'ScamLens Threat Alert';
  const closeBtn = document.createElement('button'); closeBtn.className = 'sl-close'; closeBtn.textContent = '×';
  closeBtn.onclick = () => container.remove();
  header.append(badge, title, closeBtn);
  banner.appendChild(header);

  const body = document.createElement('div');
  body.className = 'sl-body';
  body.textContent = analysis.explanation || 'This website displays deceptive indicators consistent with credential harvesting or scam activity.';
  banner.appendChild(body);

  if (analysis.evidence && analysis.evidence.length > 0) {
    const ev = document.createElement('div'); ev.className = 'sl-evidence';
    ev.textContent = `Evidence: ${analysis.evidence[0]}`;
    banner.appendChild(ev);
  }

  const actions   = document.createElement('div'); actions.className = 'sl-actions';
  const leaveBtn  = document.createElement('button'); leaveBtn.className = 'sl-btn-leave';  leaveBtn.textContent = 'Leave This Site (Safe)'; leaveBtn.onclick = () => { window.location.href = 'about:blank'; };
  const dismissBtn = document.createElement('button'); dismissBtn.className = 'sl-btn-dismiss'; dismissBtn.textContent = 'Ignore Warning'; dismissBtn.onclick = () => container.remove();
  actions.append(leaveBtn, dismissBtn);
  banner.appendChild(actions);

  shadow.appendChild(banner);
  (document.body || document.documentElement).appendChild(container);
}

// ─────────────────────────────────────────────
// 3. Link Hover Preview
// ─────────────────────────────────────────────
(function setupLinkHoverPreview() {
  // Build tooltip element
  const tooltip = document.createElement('div');
  tooltip.id = '__sl_tooltip__';
  tooltip.style.cssText = `
    position: fixed; z-index: 2147483646; pointer-events: none;
    background: rgba(8,8,12,0.97); border: 1px solid rgba(255,255,255,0.12);
    border-radius: 10px; padding: 10px 14px; font-size: 12px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    color: #e2e8f0; max-width: 320px; box-shadow: 0 8px 32px rgba(0,0,0,0.6);
    opacity: 0; transition: opacity 0.18s ease; display: none;
    backdrop-filter: blur(12px);
  `;
  (document.body || document.documentElement).appendChild(tooltip);

  let hoverTimer = null;

  function getScoreColor(score) {
    if (score >= 70) return '#ef4444';
    if (score >= 35) return '#f59e0b';
    return '#10b981';
  }

  function showTooltip(href, x, y) {
    tooltip.innerHTML = '<span style="color:#94a3b8;font-size:11px;">🔍 Scanning...</span>';
    tooltip.style.display = 'block';
    positionTooltip(x, y);
    tooltip.style.opacity = '1';

    // Ask background to analyze the URL
    try {
      chrome.runtime.sendMessage({ type: 'ANALYZE_CUSTOM_URL', url: href }, (res) => {
        if (!res || res.error) {
          tooltip.innerHTML = `<span style="color:#94a3b8;font-size:11px;">Could not analyze</span>`;
          return;
        }
        const color  = getScoreColor(res.score || 0);
        const icon   = res.verdict === 'Dangerous' ? '🚨' : res.verdict === 'Suspicious' ? '⚠️' : '✅';
        const domain = (() => { try { return new URL(href).hostname; } catch(e) { return href.slice(0,40); } })();
        tooltip.innerHTML = `
          <div style="font-weight:700;color:#fff;margin-bottom:4px;font-size:13px;">${icon} ${res.verdict}</div>
          <div style="color:#64748b;font-size:10px;margin-bottom:6px;word-break:break-all;">${domain}</div>
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="font-size:10px;color:#94a3b8;">Threat Score</span>
            <span style="font-weight:900;font-size:16px;color:${color};">${res.score}</span>
            <span style="font-size:10px;color:#94a3b8;">/ 100</span>
          </div>
          ${res.signals && res.signals.length > 0
            ? `<div style="margin-top:6px;font-size:10px;color:#94a3b8;border-top:1px solid rgba(255,255,255,0.06);padding-top:6px;">
                 ${res.signals.slice(0,2).map(s => `▶ ${s.label}`).join('<br>')}
               </div>`
            : ''}
        `;
      });
    } catch(e) {}
  }

  function positionTooltip(x, y) {
    const tw = 320, th = 120;
    const wx = window.innerWidth, wy = window.innerHeight;
    let left = x + 14, top = y + 14;
    if (left + tw > wx) left = x - tw - 10;
    if (top  + th > wy) top  = y - th - 10;
    tooltip.style.left = left + 'px';
    tooltip.style.top  = top  + 'px';
  }

  document.addEventListener('mouseover', (e) => {
    const anchor = e.target.closest('a[href]');
    if (!anchor) return;
    const href = anchor.href;
    if (!href || !href.startsWith('http')) return;

    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(() => showTooltip(href, e.clientX, e.clientY), 600);
  }, { passive: true });

  document.addEventListener('mousemove', (e) => {
    if (tooltip.style.opacity === '1') positionTooltip(e.clientX, e.clientY);
  }, { passive: true });

  document.addEventListener('mouseout', (e) => {
    if (e.target.closest('a[href]')) {
      clearTimeout(hoverTimer);
      tooltip.style.opacity = '0';
      setTimeout(() => { tooltip.style.display = 'none'; }, 200);
    }
  }, { passive: true });
})();

// ─────────────────────────────────────────────
// 4. Dark Pattern Detector
// ─────────────────────────────────────────────
function detectDarkPatterns() {
  const bodyText = document.body ? document.body.innerText : '';
  const found    = [];

  for (const dp of DARK_PATTERNS) {
    if (dp.pattern.test(bodyText)) found.push(dp);
  }

  // Also detect countdown timers in DOM
  const hasCountdown = document.querySelector('[id*="countdown" i], [class*="countdown" i], [id*="timer" i], [class*="timer" i]');
  if (hasCountdown) found.push({ label: 'Countdown Timer', icon: '⏱️' });

  if (found.length === 0) return;

  // Show a subtle warning ribbon (not as aggressive as the danger banner)
  if (document.getElementById('__sl_dark_ribbon__')) return;

  const ribbon = document.createElement('div');
  ribbon.id = '__sl_dark_ribbon__';
  ribbon.style.cssText = `
    position: fixed; bottom: 0; left: 0; right: 0; z-index: 2147483645;
    background: rgba(245,158,11,0.95); backdrop-filter: blur(10px);
    color: #000; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-size: 12px; font-weight: 600; padding: 8px 16px;
    display: flex; align-items: center; justify-content: space-between;
    box-shadow: 0 -4px 20px rgba(245,158,11,0.4);
    animation: sl-ribbon-in 0.4s ease;
  `;

  const style = document.createElement('style');
  style.textContent = `@keyframes sl-ribbon-in { from{transform:translateY(100%)} to{transform:translateY(0)} }`;
  document.head.appendChild(style);

  const labels = found.map(f => `${f.icon} ${f.label}`).join('  ·  ');
  const msg    = document.createElement('span');
  msg.textContent = `⚠️ ScamLens detected dark patterns: ${labels}`;

  const close = document.createElement('button');
  close.textContent = '×';
  close.style.cssText = 'background:transparent;border:none;font-size:18px;cursor:pointer;font-weight:900;padding:0 4px;color:#000;';
  close.onclick = () => ribbon.remove();

  ribbon.appendChild(msg);
  ribbon.appendChild(close);
  document.body.appendChild(ribbon);

  // Send telemetry
  try {
    chrome.runtime.sendMessage({
      type: 'DARK_PATTERNS_DETECTED',
      patterns: found.map(f => f.label),
      url: window.location.href
    });
  } catch(e) {}
}

// ─────────────────────────────────────────────
// 5. Notification Permission Blocker
// ─────────────────────────────────────────────
function blockNotificationAbuse() {
  // Only block on sites that look suspicious
  const host = window.location.hostname;
  const suspiciousTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.loan', '.win'];
  const isSuspicious   = suspiciousTLDs.some(tld => host.endsWith(tld));

  if (!isSuspicious) return; // Allow trusted sites to ask normally

  const original = window.Notification && window.Notification.requestPermission;
  if (!original) return;

  window.Notification.requestPermission = function() {
    console.warn('[ScamLens] Blocked notification permission request from suspicious domain:', host);
    try {
      chrome.runtime.sendMessage({ type: 'NOTIFICATION_BLOCKED', domain: host });
    } catch(e) {}
    // Return a promise that always resolves to 'denied' — site gets no popup
    return Promise.resolve('denied');
  };
}

// ─────────────────────────────────────────────
// Message Listener from Background
// ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAMLENS_VERDICT') {
    if (message.data && message.data.verdict === 'Dangerous') {
      showDangerousWarning(message.data);
    }
  }
});

// ─────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────
blockNotificationAbuse();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    sendPageSignals();
    setTimeout(detectDarkPatterns, 2000); // Wait for dynamic content
  });
} else {
  sendPageSignals();
  setTimeout(detectDarkPatterns, 2000);
}

// Observe dynamic DOM for late-loading forms
const observer = new MutationObserver(() => {
  const forms = collectFormSignals();
  if (forms.passwordForm) {
    sendPageSignals();
    observer.disconnect();
  }
});

if (document.body) {
  observer.observe(document.body, { childList: true, subtree: true });
}


// ── Target Urgency / Phishing Phrases ──
const URGENCY_PATTERNS = [
  /\bverify\s+(your\s+)?account\b/i,
  /\burgent\s+action\b/i,
  /\bimmediate\s+action\b/i,
  /\baccount\s+(suspended|blocked|locked|terminated)\b/i,
  /\bsecurity\s+alert\b/i,
  /\bunauthorized\s+access\b/i,
  /\bone-time\s+password\b/i,
  /\botp\s*(verification|required)?\b/i,
  /\benter\s+otp\b/i,
  /\bpayment\s+failed\b/i,
  /\bupdate\s+billing\b/i,
  /\bconfirm\s+identity\b/i,
  /\bkyc\s+update\b/i,
  /\bpan\s+verification\b/i,
  /\baadhaar\s+verify\b/i,
  /\bclaim\s+reward\b/i,
  /\blimited\s+time\b/i
];

/**
 * Collects form inputs and destination targets
 * @returns {{ passwordForm: boolean, formTargetHost: string | null }}
 */
function collectFormSignals() {
  const forms = document.querySelectorAll('form');
  let passwordForm = false;
  let formTargetHost = null;

  for (const form of forms) {
    const hasPassword = form.querySelector('input[type="password"]');
    const hasPayment = form.querySelector('input[name*="card" i], input[name*="cvv" i], input[autocomplete*="cc-" i], input[id*="card" i], input[id*="cvv" i]');

    if (hasPassword || hasPayment) {
      passwordForm = true;
      try {
        const rawAction = form.getAttribute('action') || window.location.href;
        const resolvedUrl = new URL(rawAction, window.location.href);
        formTargetHost = resolvedUrl.hostname.toLowerCase();
      } catch (e) {
        formTargetHost = window.location.hostname.toLowerCase();
      }
      break;
    }
  }

  // Fallback: Check inputs not enclosed in <form>
  if (!passwordForm) {
    const loosePassword = document.querySelector('input[type="password"]');
    if (loosePassword) {
      passwordForm = true;
      formTargetHost = window.location.hostname.toLowerCase();
    }
  }

  return { passwordForm, formTargetHost };
}

/**
 * Scans visible page text for psychological urgency patterns
 * @returns {string[]}
 */
function collectKeywordSignals() {
  const bodyText = (document.body ? document.body.innerText : '') || '';
  const sample = bodyText.slice(0, 40000);
  const hits = [];

  for (const pattern of URGENCY_PATTERNS) {
    const match = sample.match(pattern);
    if (match) {
      hits.push(match[0].toLowerCase());
    }
  }

  return [...new Set(hits)];
}

/**
 * Transmits collected page signals to background worker
 */
function sendPageSignals() {
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) return;

  try {
    const forms = collectFormSignals();
    const keywords = collectKeywordSignals();

    chrome.runtime.sendMessage({
      type: 'PAGE_SIGNALS',
      url: window.location.href,
      pageSignals: {
        passwordForm: forms.passwordForm,
        formTargetHost: forms.formTargetHost,
        keywordHits: keywords
      }
    });
  } catch (err) {
    // Context invalidated on extension reload
  }
}

// ── In-Page Dangerous Threat Banner (Shadow DOM) ──
function showDangerousWarning(analysis) {
  if (document.getElementById('scamlens-warning-container')) return;

  const container = document.createElement('div');
  container.id = 'scamlens-warning-container';

  const shadow = container.attachShadow({ mode: 'closed' });

  // Stylesheet
  const style = document.createElement('style');
  style.textContent = `
    .sl-banner {
      position: fixed;
      top: 16px;
      right: 16px;
      max-width: 420px;
      background: #180909;
      color: #ffffff;
      border: 1px solid #ef4444;
      border-radius: 12px;
      padding: 16px;
      box-shadow: 0 12px 36px rgba(0,0,0,0.7), 0 0 20px rgba(239,68,68,0.25);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      z-index: 2147483647;
      animation: slSlideDown 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }
    @keyframes slSlideDown {
      from { transform: translateY(-20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    .sl-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
    }
    .sl-badge {
      background: #ef4444;
      color: #ffffff;
      font-size: 11px;
      font-weight: 800;
      padding: 3px 8px;
      border-radius: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .sl-title {
      font-weight: 700;
      font-size: 14px;
      color: #fca5a5;
    }
    .sl-close {
      margin-left: auto;
      background: transparent;
      border: none;
      color: #9ca3af;
      font-size: 18px;
      cursor: pointer;
      padding: 4px 8px;
      border-radius: 4px;
    }
    .sl-close:hover { color: #ffffff; background: rgba(255,255,255,0.1); }
    .sl-body {
      color: #e5e7eb;
      margin-bottom: 12px;
      font-size: 12.5px;
    }
    .sl-evidence {
      background: rgba(255,255,255,0.05);
      border-left: 3px solid #ef4444;
      padding: 6px 10px;
      border-radius: 4px;
      font-size: 11.5px;
      color: #fecaca;
      margin-bottom: 12px;
    }
    .sl-actions {
      display: flex;
      gap: 8px;
    }
    .sl-btn-leave {
      flex: 1;
      background: #ef4444;
      color: #ffffff;
      border: none;
      border-radius: 6px;
      padding: 8px 12px;
      font-weight: 700;
      font-size: 12px;
      cursor: pointer;
      text-align: center;
    }
    .sl-btn-leave:hover { background: #dc2626; }
    .sl-btn-dismiss {
      background: rgba(255,255,255,0.1);
      color: #d1d5db;
      border: 1px solid rgba(255,255,255,0.15);
      border-radius: 6px;
      padding: 8px 12px;
      font-weight: 600;
      font-size: 12px;
      cursor: pointer;
    }
    .sl-btn-dismiss:hover { background: rgba(255,255,255,0.18); color: #ffffff; }
  `;
  shadow.appendChild(style);

  // Card Structure built safely using DOM nodes and textContent
  const banner = document.createElement('div');
  banner.className = 'sl-banner';
  banner.setAttribute('role', 'alert');

  const header = document.createElement('div');
  header.className = 'sl-header';

  const badge = document.createElement('span');
  badge.className = 'sl-badge';
  badge.textContent = 'DANGEROUS';

  const title = document.createElement('span');
  title.className = 'sl-title';
  title.textContent = 'ScamLens Threat Alert';

  const closeBtn = document.createElement('button');
  closeBtn.className = 'sl-close';
  closeBtn.setAttribute('aria-label', 'Dismiss alert');
  closeBtn.textContent = '×';
  closeBtn.onclick = () => container.remove();

  header.appendChild(badge);
  header.appendChild(title);
  header.appendChild(closeBtn);
  banner.appendChild(header);

  const body = document.createElement('div');
  body.className = 'sl-body';
  body.textContent = analysis.explanation || 'This website displays deceptive indicators consistent with credential harvesting or scam activity.';
  banner.appendChild(body);

  if (analysis.evidence && analysis.evidence.length > 0) {
    const evidence = document.createElement('div');
    evidence.className = 'sl-evidence';
    evidence.textContent = `Evidence: ${analysis.evidence[0]}`;
    banner.appendChild(evidence);
  }

  const actions = document.createElement('div');
  actions.className = 'sl-actions';

  const leaveBtn = document.createElement('button');
  leaveBtn.className = 'sl-btn-leave';
  leaveBtn.textContent = 'Leave This Site (Safe)';
  leaveBtn.onclick = () => {
    window.location.href = 'about:blank';
  };

  const dismissBtn = document.createElement('button');
  dismissBtn.className = 'sl-btn-dismiss';
  dismissBtn.textContent = 'Ignore Warning';
  dismissBtn.onclick = () => container.remove();

  actions.appendChild(leaveBtn);
  actions.appendChild(dismissBtn);
  banner.appendChild(actions);

  shadow.appendChild(banner);
  (document.body || document.documentElement).appendChild(container);
}

// ── Web Page & Extension Telemetry Bridge ──
window.addEventListener('message', (event) => {
  if (event.source !== window || !event.data) return;
  if (event.data.type === 'SCAMLENS_REQUEST_DASHBOARD_DATA') {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['dashboardStats', 'shieldActive', 'activityLog', 'currentSiteStats'], (data) => {
        window.postMessage({ type: 'SCAMLENS_RESPONSE_DASHBOARD_DATA', data }, '*');
      });
    }
  }
});

// ── Relay Anti-Fingerprinting Telemetry from Main World to Background ──
window.addEventListener('ds-telemetry-event', (e) => {
  if (e.detail && typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage(e.detail);
  }
});

// ── Message Listener from Background ──
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAMLENS_VERDICT') {
    if (message.data && message.data.verdict === 'Dangerous') {
      showDangerousWarning(message.data);
    }
  }
});

// ── Execution Entry Point ──
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    sendPageSignals();
  });
} else {
  sendPageSignals();
}

// Observe dynamic DOM changes (e.g. login modal dynamically added)
const observer = new MutationObserver(() => {
  const forms = collectFormSignals();
  if (forms.passwordForm) {
    sendPageSignals();
    observer.disconnect(); // Once detected, stop observer
  }
});

if (document.body) {
  observer.observe(document.body, { childList: true, subtree: true });
}
