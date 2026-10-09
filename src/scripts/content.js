/**
 * ScamLens Content Script (content.js)
 * 
 * Collects page signals for the rules engine:
 * 1. Forms with password or payment fields
 * 2. Form submission targets (detecting cross-domain posts)
 * 3. High-pressure urgency / OTP / security alert phrases
 * 
 * Injects non-intrusive warning banners for Dangerous sites using Shadow DOM.
 * Strict XSS prevention: Uses textContent exclusively for dynamic text.
 */

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
