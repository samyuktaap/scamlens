/**
 * ScamLens Web Scanner Controller (web-scanner.js)
 * "Rules decide. AI explains."
 * 
 * Drives the live paste-a-link interactive threat scanner on the ScamLens web page.
 * Uses rules.js directly in the browser for instant, 100% offline-capable analysis.
 * Supports querying the local fallback server or Google Apps Script Web App for Gemini explanation.
 */

import { analyzeUrl, getVerdictAdvice } from './rules.js';

// Pre-configured threat test presets for judges & evaluators
export const PRESETS = [
  {
    name: '🟢 Google (Safe)',
    url: 'https://www.google.com',
    desc: 'Top 10,000 verified domain allowlist'
  },
  {
    name: '🔴 Microsoft Spoof (Phish)',
    url: 'http://login.micros0ft-verify.com/account/login',
    desc: 'Brand look-alike typo + No HTTPS'
  },
  {
    name: '🟡 Raw IP Host',
    url: 'http://192.168.1.1/admin',
    desc: 'Direct IPv4 literal address'
  },
  {
    name: '🔴 Netflix Look-alike (.xyz)',
    url: 'http://netflix-billing-update.xyz/login',
    desc: 'Hyphenated brand look-alike + abused TLD'
  },
  {
    name: '🔴 Punycode Homograph',
    url: 'http://xn--gogle-pra.com/auth',
    desc: 'IDN Unicode character spoofing'
  },
  {
    name: '🔴 SBI Portal Phish (.buzz)',
    url: 'http://sbi-portal-verify.buzz/login',
    desc: 'Banking brand + abused .buzz TLD'
  }
];

export function initWebScanner() {
  const urlInput = document.getElementById('scanner-url-input');
  const scanBtn = document.getElementById('scanner-btn');
  const presetsContainer = document.getElementById('scanner-presets');
  const resultsCard = document.getElementById('scanner-results');
  const verdictBadge = document.getElementById('scanner-verdict');
  const scoreNumber = document.getElementById('scanner-score');
  const scoreBar = document.getElementById('scanner-score-bar');
  const explanationText = document.getElementById('scanner-explanation');
  const sourcePill = document.getElementById('scanner-source');
  const signalsList = document.getElementById('scanner-signals');
  const adviceList = document.getElementById('scanner-advice');
  const btnGemini = document.getElementById('scanner-gemini-btn');
  const deepStatus = document.getElementById('scanner-deep-status');

  if (!urlInput || !scanBtn) return;

  // Render preset buttons
  if (presetsContainer) {
    presetsContainer.textContent = '';
    PRESETS.forEach(preset => {
      const btn = document.createElement('button');
      btn.className = 'preset-chip';
      btn.type = 'button';
      btn.textContent = preset.name;
      btn.title = preset.desc;
      btn.onclick = () => {
        urlInput.value = preset.url;
        runScan(preset.url);
      };
      presetsContainer.appendChild(btn);
    });
  }

  let latestAnalysis = null;

  function runScan(inputUrl) {
    const rawUrl = (inputUrl || urlInput.value || '').trim();
    if (!rawUrl) {
      urlInput.focus();
      return;
    }

    // Run deterministic rules engine
    const analysis = analyzeUrl(rawUrl);
    latestAnalysis = analysis;

    // Display results
    if (resultsCard) {
      resultsCard.style.display = 'block';
      resultsCard.className = `scanner-results-card state-${analysis.verdict.toLowerCase()}`;
    }

    if (verdictBadge) {
      verdictBadge.textContent = analysis.verdict.toUpperCase();
    }

    if (scoreNumber) {
      scoreNumber.textContent = `${analysis.score}/100`;
    }

    if (scoreBar) {
      scoreBar.style.width = `${Math.min(100, analysis.score)}%`;
      if (analysis.verdict === 'Dangerous') {
        scoreBar.style.background = '#ef4444';
      } else if (analysis.verdict === 'Suspicious') {
        scoreBar.style.background = '#f59e0b';
      } else {
        scoreBar.style.background = '#10b981';
      }
    }

    if (explanationText) {
      explanationText.textContent = analysis.explanation;
    }

    if (sourcePill) {
      sourcePill.textContent = '🛡️ Deterministic Rules Engine';
      sourcePill.className = 'source-pill source-rules';
    }

    // Signals
    if (signalsList) {
      signalsList.textContent = '';
      if (!analysis.signals || analysis.signals.length === 0) {
        const emptyLi = document.createElement('li');
        emptyLi.className = 'sig-empty';
        emptyLi.textContent = analysis.isAllowlisted
          ? '✓ Verified popular domain on Tranco Top 10K allowlist.'
          : '✓ No suspicious domain or URL anomalies triggered.';
        signalsList.appendChild(emptyLi);
      } else {
        analysis.signals.forEach(sig => {
          const li = document.createElement('li');
          li.className = 'sig-item';

          const tag = document.createElement('span');
          tag.className = 'sig-tag';
          tag.textContent = `+${sig.points} pts`;

          const label = document.createElement('span');
          label.className = 'sig-label';
          label.textContent = sig.evidence || sig.label;

          li.appendChild(tag);
          li.appendChild(label);
          signalsList.appendChild(li);
        });
      }
    }

    // Actionable advice
    if (adviceList) {
      adviceList.textContent = '';
      const advice = Array.isArray(analysis.advice) ? analysis.advice : [analysis.advice];
      advice.forEach(adv => {
        const li = document.createElement('li');
        li.className = 'adv-item';
        li.textContent = adv;
        adviceList.appendChild(li);
      });
    }

    if (btnGemini) {
      btnGemini.disabled = false;
    }
    if (deepStatus) {
      deepStatus.textContent = '';
    }
  }

  // Hook scan button & enter key
  scanBtn.onclick = () => runScan();
  urlInput.onkeydown = (e) => {
    if (e.key === 'Enter') runScan();
  };

  // Deep Check with Gemini AI Explainer
  if (btnGemini) {
    btnGemini.onclick = async () => {
      if (!latestAnalysis) return;

      btnGemini.disabled = true;
      if (deepStatus) {
        deepStatus.textContent = '✨ Querying Gemini Flash explainer...';
        deepStatus.className = 'deep-status active';
      }

      // Try local fallback server or Apps Script endpoint
      const endpoints = [
        'http://localhost:3000/api/check'
      ];

      let enriched = null;
      for (const endpoint of endpoints) {
        try {
          const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              token: 'scamlens-demo-token',
              url: latestAnalysis.url,
              verdict: latestAnalysis.verdict,
              score: latestAnalysis.score,
              evidence: latestAnalysis.signals.map(s => s.evidence || s.label)
            })
          });
          if (res.ok) {
            enriched = await res.json();
            break;
          }
        } catch (e) {}
      }

      if (enriched && enriched.plainExplanation) {
        if (explanationText) explanationText.textContent = enriched.plainExplanation;
        if (sourcePill) {
          sourcePill.textContent = enriched.source === 'gemini' ? '✨ Gemini AI Explainer' : '🛡️ Deterministic Safety Engine';
          sourcePill.className = enriched.source === 'gemini' ? 'source-pill source-gemini' : 'source-pill source-rules';
        }
        if (adviceList && enriched.advice) {
          adviceList.textContent = '';
          const advArray = Array.isArray(enriched.advice) ? enriched.advice : [enriched.advice];
          advArray.forEach(adv => {
            const li = document.createElement('li');
            li.className = 'adv-item';
            li.textContent = adv;
            adviceList.appendChild(li);
          });
        }
        if (deepStatus) {
          deepStatus.textContent = enriched.source === 'gemini' ? '✓ AI plain-language rewrite applied!' : '✓ Evaluated via fallback template.';
        }
      } else {
        // Deterministic template rewrite
        const fallback = getVerdictAdvice(latestAnalysis.verdict, latestAnalysis.score, latestAnalysis.signals);
        if (explanationText) explanationText.textContent = fallback.plainExplanation;
        if (sourcePill) {
          sourcePill.textContent = '🛡️ Offline Rules Explainer';
          sourcePill.className = 'source-pill source-rules';
        }
        if (deepStatus) {
          deepStatus.textContent = '✓ Offline explanation applied (no backend needed).';
        }
      }
      btnGemini.disabled = false;
    };
  }

  // Pre-scan the first malicious preset so evaluators immediately see live results
  urlInput.value = 'http://login.micros0ft-verify.com/account/login';
  runScan(urlInput.value);
}

// Auto-initialize when DOM is ready
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initWebScanner);
  } else {
    initWebScanner();
  }
}
