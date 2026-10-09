/**
 * ScamLens Popup Controller (popup.js)
 * "Rules decide. AI explains."
 * 
 * Strict XSS Defense: All page-derived hostnames, evidence strings,
 * and explanation text are rendered exclusively via textContent.
 * Full WCAG AA keyboard and aria-live compliance.
 */

document.addEventListener('DOMContentLoaded', async () => {
  // DOM References
  const verdictCard = document.getElementById('verdict-card');
  const targetDomainEl = document.getElementById('target-domain');
  const verdictTextEl = document.getElementById('verdict-text');
  const verdictIconEl = document.getElementById('verdict-icon');
  const threatScoreEl = document.getElementById('threat-score');
  const explanationEl = document.getElementById('explanation-text');
  const modeTagEl = document.getElementById('mode-tag');
  const evidenceListEl = document.getElementById('evidence-list');
  const evidenceCountEl = document.getElementById('evidence-count');
  const adviceListEl = document.getElementById('advice-list');
  const btnDeepCheck = document.getElementById('btn-deep-check');
  const deepCheckLabel = document.getElementById('deep-check-label');
  const shieldToggle = document.getElementById('shield-toggle');
  const whitelistToggle = document.getElementById('whitelist-toggle');
  const btnNuke = document.getElementById('btn-nuke');
  const btnDashboard = document.getElementById('btn-dashboard');
  const btnReport = document.getElementById('btn-report');

  let currentAnalysis = null;
  let activeTabUrl = '';
  let activeTabDomain = '';

  /**
   * Safely renders verdict and evidence strictly using textContent
   * @param {Object} analysis 
   */
  function renderAnalysis(analysis) {
    if (!analysis) return;
    currentAnalysis = analysis;

    const verdict = analysis.verdict || 'Safe';
    const score = analysis.score !== undefined ? analysis.score : 0;
    const host = analysis.host || 'Active Page';

    // 1. Update Hero Card
    verdictCard.className = `verdict-card state-${verdict.toLowerCase()}`;
    targetDomainEl.textContent = host;
    verdictTextEl.textContent = verdict;
    threatScoreEl.textContent = score;
    explanationEl.textContent = analysis.explanation || 'Rules evaluation completed.';

    // Accessible Icon + Text
    if (verdict === 'Dangerous') {
      verdictIconEl.textContent = '🚨';
    } else if (verdict === 'Suspicious') {
      verdictIconEl.textContent = '⚠️';
    } else {
      verdictIconEl.textContent = '🛡️';
    }

    if (modeTagEl) {
      modeTagEl.textContent = analysis.mode === 'online' ? 'Online Enriched' : 'Offline First';
    }

    // 2. Render Evidence List
    evidenceListEl.textContent = ''; // Clear existing children
    const signals = Array.isArray(analysis.signals) ? analysis.signals : [];
    evidenceCountEl.textContent = `${signals.length} signal${signals.length === 1 ? '' : 's'}`;

    if (signals.length === 0) {
      const emptyItem = document.createElement('li');
      emptyItem.className = 'evidence-item';
      emptyItem.textContent = analysis.isAllowlisted
        ? 'Verified popular domain. No brand impersonation or cross-domain credential targets detected.'
        : 'No deceptive URL anomalies, brand look-alikes, or phishing indicators detected.';
      evidenceListEl.appendChild(emptyItem);
    } else {
      signals.forEach(sig => {
        const item = document.createElement('li');
        item.className = 'evidence-item';

        const tag = document.createElement('div');
        tag.className = 'evidence-tag';
        tag.textContent = `▶ ${sig.label} (+${sig.points} pts)`;

        const text = document.createElement('div');
        text.textContent = sig.evidence || sig.label;

        item.appendChild(tag);
        item.appendChild(text);
        evidenceListEl.appendChild(item);
      });
    }

    // 3. Render Actionable Advice
    adviceListEl.textContent = '';
    const adviceItems = Array.isArray(analysis.advice) ? analysis.advice : [];

    adviceItems.forEach(adv => {
      const item = document.createElement('li');
      item.className = 'advice-item';

      const icon = document.createElement('span');
      icon.className = 'advice-icon';
      icon.textContent = verdict === 'Dangerous' ? '✕' : (verdict === 'Suspicious' ? '!' : '✓');

      const text = document.createElement('span');
      text.textContent = adv;

      item.appendChild(icon);
      item.appendChild(text);
      adviceListEl.appendChild(item);
    });
  }

  // ── 1. Fetch Current Analysis from Background ──
  chrome.runtime.sendMessage({ type: 'GET_CURRENT_VERDICT' }, (response) => {
    if (response && !response.error) {
      renderAnalysis(response);
    } else {
      targetDomainEl.textContent = 'No active web page';
      explanationEl.textContent = 'Open any website to inspect URL safety and track protection.';
    }
  });

  // ── 2. Initialize Active Tab Context & Allowlist Toggle ──
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url && tabs[0].url.startsWith('http')) {
      activeTabUrl = tabs[0].url;
      try {
        activeTabDomain = new URL(activeTabUrl).hostname;
      } catch (e) {}

      if (activeTabDomain) {
        chrome.runtime.sendMessage({ type: 'CHECK_WHITELIST', domain: activeTabDomain }, (res) => {
          if (res && res.isWhitelisted) {
            whitelistToggle.classList.add('active');
            whitelistToggle.textContent = 'ON';
            whitelistToggle.setAttribute('aria-pressed', 'true');
          }
        });

        whitelistToggle.onclick = () => {
          const isActive = whitelistToggle.classList.toggle('active');
          whitelistToggle.textContent = isActive ? 'ON' : 'OFF';
          whitelistToggle.setAttribute('aria-pressed', String(isActive));

          if (isActive) {
            chrome.runtime.sendMessage({ type: 'ADD_WHITELIST', domain: activeTabDomain });
          } else {
            chrome.runtime.sendMessage({ type: 'REMOVE_WHITELIST', domain: activeTabDomain });
          }
          setTimeout(() => chrome.tabs.reload(tabs[0].id), 400);
        };
      }
    } else {
      whitelistToggle.disabled = true;
      btnDeepCheck.disabled = true;
    }
  });

  // ── 3. Initialize Shield Toggle ──
  chrome.storage.local.get('shieldActive', (data) => {
    const isShieldOn = Boolean(data.shieldActive);
    if (isShieldOn) {
      shieldToggle.classList.add('active');
      shieldToggle.textContent = 'ON';
      shieldToggle.setAttribute('aria-pressed', 'true');
    }
  });

  shieldToggle.onclick = () => {
    const isActive = shieldToggle.classList.toggle('active');
    shieldToggle.textContent = isActive ? 'ON' : 'OFF';
    shieldToggle.setAttribute('aria-pressed', String(isActive));

    if (isActive) {
      chrome.runtime.sendMessage({ type: 'ENABLE_SHIELD' });
    } else {
      chrome.runtime.sendMessage({ type: 'DISABLE_SHIELD' });
    }
  };

  // ── 4. Deep Check Action (DNS / RDAP Enrichment) ──
  btnDeepCheck.onclick = () => {
    btnDeepCheck.disabled = true;
    deepCheckLabel.textContent = 'Querying Google Public DNS...';

    chrome.runtime.sendMessage({ type: 'RUN_DEEP_CHECK' }, (enriched) => {
      if (enriched && !enriched.error) {
        renderAnalysis(enriched);
        deepCheckLabel.textContent = '✓ Deep Check Completed';
      } else {
        deepCheckLabel.textContent = 'Lookup Failed (Offline)';
        setTimeout(() => {
          btnDeepCheck.disabled = false;
          deepCheckLabel.textContent = 'Deep Check (DNS & RDAP)';
        }, 2000);
      }
    });
  };

  // ── 5. Detonate Privacy Nuke ──
  btnNuke.onclick = () => {
    if (!activeTabUrl) return;

    btnNuke.disabled = true;
    btnNuke.textContent = '☣️ Nuking Site Artifacts...';

    chrome.runtime.sendMessage({ type: 'DETONATE_NUKE', url: activeTabUrl }, (res) => {
      btnNuke.textContent = '✅ Cookies & Storage Cleared';
      setTimeout(() => {
        btnNuke.disabled = false;
        btnNuke.textContent = '☢️ Clean Cookies & Storage';
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]) chrome.tabs.reload(tabs[0].id);
        });
      }, 1000);
    });
  };

  // ── 6. Footer Navigation ──
  btnDashboard.onclick = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/pages/dashboard.html') });
  };

  btnReport.onclick = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/pages/report.html') });
  };
});
