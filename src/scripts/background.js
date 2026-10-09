/**
 * ScamLens Background Service Worker (background.js)
 * "Rules decide. AI explains."
 * 
 * 100% Local, Offline-First Architecture.
 * Evaluates rules.js locally on navigation, manages toolbar badges,
 * caches per-tab verdicts, and handles optional backend enrichment.
 */

import { analyzeUrl, POPULAR_DOMAINS, getVerdictAdvice } from './rules.js';
import { TelemetryProcessor } from './telemetry.js';

// ── In-Memory Caches ──
const tabVerdicts = new Map();         // tabId -> Analysis Result
const tabSignals = new Map();          // tabId -> in-page DOM signals
const tabExternalSignals = new Map();  // tabId -> backend RDAP/DNS/SafeBrowsing signals

// Dynamic Blocklist — 50 Major Tracker Domains (Domain-Anchored)
const TRACKER_BLOCKLIST = [
  // Ad Networks
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
  'adnxs.com', 'adsrvr.org', 'advertising.com', 'adform.net',
  'criteo.com', 'criteo.net', 'casalemedia.com', 'openx.net',
  'pubmatic.com', 'rubiconproject.com', 'smartadserver.com',
  'taboola.com', 'outbrain.com', 'amazon-adsystem.com',
  'moatads.com', 'serving-sys.com', 'bidswitch.net',
  // Analytics & Tracking
  'google-analytics.com', 'googletagmanager.com', 'googletagservices.com',
  'hotjar.com', 'fullstory.com', 'mixpanel.com', 'segment.io',
  'segment.com', 'amplitude.com', 'newrelic.com', 'nr-data.net',
  'scorecardresearch.com', 'quantserve.com', 'chartbeat.com',
  // Social Tracking Pixels
  'facebook.com', 'facebook.net', 'connect.facebook.net',
  'pixel.facebook.com', 'analytics.twitter.com', 't.co',
  'snap.licdn.com', 'px.ads.linkedin.com', 'bat.bing.com',
  // Data Brokers / Fingerprinting
  'bluekai.com', 'exelator.com', 'demdex.net', 'krxd.net',
  'rlcdn.com', 'agkn.com', 'turn.com', 'mathtag.com',
  'tapad.com', 'eyeota.net', 'quantcount.com', 'quantserve.com',
  'adtech.de', 'afy11.net', 'yieldmo.com', 'zemanta.com',
  'revcontent.com', 'liadm.com', 'liadm.net', 'ads-twitter.com',
  'clarity.ms', 'mookie1.com', 'omtrdc.net', 'everesttech.net',
  'adbrn.com', 'fastpeoplesearch.com', 'whitepages.com', 'spokeo.com',
  'mylife.com', 'truepeoplesearch.com', 'instantcheckmate.com', 'beenverified.com'
];

// ── Lifecycle Handlers ──
chrome.runtime.onStartup.addListener(async () => {
  await ensureStatsInitialized();
  const { shieldActive } = await getStorage('shieldActive');
  if (shieldActive) {
    enableShadowShield();
    console.log('[ScamLens] Shield auto-restored on startup.');
  }
  setupContextMenus();
});

chrome.runtime.onInstalled.addListener(async (details) => {
  const { shieldActive } = await getStorage('shieldActive');
  if (shieldActive) enableShadowShield();
  await ensureStatsInitialized();
  setupContextMenus();

  if (details.reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/pages/onboard.html') });
  }
});

// ── Context Menu Setup ──
function setupContextMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: 'scamlens-scan-link',
      title: '🔍 Scan with ScamLens',
      contexts: ['link'],
    });
    chrome.contextMenus.create({
      id: 'scamlens-scan-page',
      title: '🛡️ ScamLens: Check This Page',
      contexts: ['page'],
    });
    chrome.contextMenus.create({
      id: 'scamlens-scan-selection',
      title: '🔍 Scan Selected URL',
      contexts: ['selection'],
    });
  });
}

// ── Context Menu Click Handler ──
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  let targetUrl = '';

  if (info.menuItemId === 'scamlens-scan-link') {
    targetUrl = info.linkUrl || '';
  } else if (info.menuItemId === 'scamlens-scan-page') {
    targetUrl = tab.url || '';
  } else if (info.menuItemId === 'scamlens-scan-selection') {
    const sel = (info.selectionText || '').trim();
    targetUrl = /^https?:\/\//i.test(sel) ? sel : 'https://' + sel;
  }

  if (!targetUrl || !targetUrl.startsWith('http')) return;

  try {
    const analysis = analyzeUrl(targetUrl);

    // Show result as notification
    const icon = analysis.verdict === 'Dangerous' ? '🚨' : analysis.verdict === 'Suspicious' ? '⚠️' : '✅';
    const color = analysis.verdict === 'Dangerous' ? 'DANGEROUS' : analysis.verdict === 'Suspicious' ? 'SUSPICIOUS' : 'SAFE';

    chrome.notifications.create(`scan-${Date.now()}`, {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('public/icon128.png'),
      title: `ScamLens: ${color} (Score: ${analysis.score}/100)`,
      message: analysis.explanation || analysis.plainExplanation || `${new URL(targetUrl).hostname} — ${analysis.verdict}`,
      priority: analysis.verdict === 'Dangerous' ? 2 : 1,
    });

    // Also store result so popup can show it
    await chrome.storage.local.set({ contextMenuResult: { url: targetUrl, ...analysis, timestamp: Date.now() } });
  } catch (e) {
    console.warn('[ScamLens Context Menu] Error:', e);
  }
});

// Clean up memory maps when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabVerdicts.delete(tabId);
  tabSignals.delete(tabId);
  tabExternalSignals.delete(tabId);
});

// ── Badge Management ──
function updateToolbarBadge(tabId, verdict, score) {
  if (!tabId || tabId < 0) return;

  try {
    if (verdict === 'Dangerous') {
      chrome.action.setBadgeText({ tabId, text: '!' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#ef4444' }); // Red
    } else if (verdict === 'Suspicious') {
      chrome.action.setBadgeText({ tabId, text: `${score}` });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#f59e0b' }); // Amber
    } else {
      chrome.action.setBadgeText({ tabId, text: '✓' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#10b981' }); // Green
    }
  } catch (err) {
    // Tab might have closed
  }
}

// ── Tab Evaluation Core ──
export async function evaluateTabScamLens(tabId, url) {
  if (!url || !url.startsWith('http')) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return null;
  }

  const pSignals = tabSignals.get(tabId) || {};
  const extSignals = tabExternalSignals.get(tabId) || {};

  // Deterministic rules execution (< 1ms offline)
  const analysis = analyzeUrl(url, pSignals, extSignals);

  tabVerdicts.set(tabId, analysis);
  updateToolbarBadge(tabId, analysis.verdict, analysis.score);

  // ── Push Notification for Dangerous Sites ──
  if (analysis.verdict === 'Dangerous') {
    const notifKey = `notified_${analysis.host}`;
    const already = await getStorage(notifKey);
    if (!already[notifKey]) {
      chrome.notifications.create(`threat-${Date.now()}`, {
        type: 'basic',
        iconUrl: chrome.runtime.getURL('public/icon128.png'),
        title: '🚨 ScamLens: DANGEROUS SITE DETECTED',
        message: `${analysis.host} — ${analysis.explanation || 'Phishing or scam indicators detected. Do not enter credentials.'}`,
        priority: 2,
      });
      // Suppress repeat notifications for same domain for 1 hour
      const suppress = {};
      suppress[notifKey] = true;
      chrome.storage.local.set(suppress);
      setTimeout(() => chrome.storage.local.remove(notifKey), 3600000);
    }
  }

  // Persist latest active evaluation for popup / dashboard
  await chrome.storage.local.set({
    lastAnalysis: analysis,
    currentSiteStats: {
      domain: analysis.host,
      score: analysis.score,
      verdict: analysis.verdict,
      riskLevel: analysis.verdict.toUpperCase(),
      signals: analysis.signals,
      advice: analysis.advice,
      explanation: analysis.explanation,
      mode: analysis.mode
    }
  });

  // Track unique protected domains for dashboard stats
  if (analysis.host) {
    try {
      const { dashboardStats = {} } = await getStorage('dashboardStats');
      const stats = normalizeStats(dashboardStats);
      const domains = stats.protectedDomains || [];
      if (!domains.includes(analysis.host)) {
        domains.push(analysis.host);
        stats.protectedDomains = domains.slice(-200); // keep last 200
        stats.sessionsProtected = domains.length;
        ensureTodayBucket(stats);
        stats.weeklyData[todayKey()].sessions = (stats.weeklyData[todayKey()].sessions || 0) + 1;
        await chrome.storage.local.set({ dashboardStats: stats });
      }
    } catch (e) {}
  }

  // Notify content script
  try {
    chrome.tabs.sendMessage(tabId, {
      type: 'SCAMLENS_VERDICT',
      data: analysis
    }).catch(() => {});
  } catch (e) {}

  return analysis;
}

// ── Navigation Listeners ──
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    evaluateTabScamLens(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && tab.url.startsWith('http')) {
      evaluateTabScamLens(activeInfo.tabId, tab.url);
    }
  } catch (err) {}
});

// ── Real-Time Tracker Interceptor ──
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.type !== 'main_frame' && details.url.startsWith('http')) {
      try {
        const { shieldActive } = await getStorage('shieldActive');
        if (!shieldActive) return; // Only count when shield is ON

        const url = new URL(details.url);
        const domain = url.hostname.toLowerCase();

        // Exact domain-anchored blocklist match
        const isTracker = TRACKER_BLOCKLIST.some(blocked => domain === blocked || domain.endsWith('.' + blocked));

        if (isTracker) {
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0] && tabs[0].url) {
              const siteDomain = new URL(tabs[0].url).hostname.toLowerCase();
              if (domain === siteDomain || siteDomain.endsWith('.' + domain)) return;

              recordBlockEvent(1, siteDomain, domain, details.type);
            }
          });
        }
      } catch (e) {}
    }
  },
  { urls: ["<all_urls>"] }
);

// ── DeclarativeNetRequest Dynamic Shield ──
async function enableShadowShield() {
  const { whitelistedSites = [] } = await getStorage('whitelistedSites');
  const resourceTypes = ['script', 'image', 'xmlhttprequest', 'sub_frame', 'stylesheet', 'font', 'ping'];

  const rules = TRACKER_BLOCKLIST.map((domain, index) => {
    let rule = {
      id: index + 1,
      priority: 1,
      action: { type: 'block' },
      condition: {
        urlFilter: `||${domain}^`,
        resourceTypes,
        domainType: 'thirdParty'
      }
    };
    if (whitelistedSites.length > 0) {
      rule.condition.excludedInitiatorDomains = whitelistedSites;
    }
    return rule;
  });

  const allIds = rules.map(r => r.id);

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: allIds,
    addRules: rules
  });

  console.log(`[ScamLens] Shield active: ${rules.length} domain-anchored rules enforced.`);
}

async function disableShadowShield() {
  const allIds = TRACKER_BLOCKLIST.map((_, i) => i + 1);
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: allIds
  });
  console.log("[ScamLens] Shield disabled.");
}

// ── Privacy Nuke: Clean site cookies & storage ──
async function nukeSiteData(pageUrl) {
  const domain = new URL(pageUrl).hostname;
  const cookies = await chrome.cookies.getAll({ domain });

  for (let cookie of cookies) {
    const protocol = cookie.secure ? "https:" : "http:";
    const cleanDomain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
    const cookieUrl = `${protocol}//${cleanDomain}${cookie.path}`;
    await chrome.cookies.remove({ url: cookieUrl, name: cookie.name }).catch(() => {});
  }

  // Find any tab showing this domain (not just the active one, since popup may be active)
  const allTabs = await chrome.tabs.query({});
  const matchingTab = allTabs.find(t => t.url && t.url.includes(domain));
  if (matchingTab) {
    await chrome.scripting.executeScript({
      target: { tabId: matchingTab.id },
      func: () => {
        try {
          localStorage.clear();
          sessionStorage.clear();
        } catch (e) {}
      }
    }).catch(() => {});
  }

  await recordCookieClean(cookies.length + 10, domain);
  return { success: true, cookiesNuked: cookies.length };
}

// ── Messaging Router ──
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Page Signals from Content Script
  if (message.type === 'PAGE_SIGNALS' && sender.tab) {
    tabSignals.set(sender.tab.id, message.pageSignals);
    evaluateTabScamLens(sender.tab.id, message.url || sender.tab.url);
    sendResponse({ received: true });
    return true;
  }

  // Popup requesting current active tab verdict
  if (message.type === 'GET_CURRENT_VERDICT') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const activeTab = tabs[0];
      if (!activeTab || !activeTab.url || !activeTab.url.startsWith('http')) {
        sendResponse({ error: 'No active web page' });
        return;
      }

      let verdict = tabVerdicts.get(activeTab.id);
      if (!verdict) {
        verdict = await evaluateTabScamLens(activeTab.id, activeTab.url);
      }
      sendResponse(verdict);
    });
    return true; // Keep channel open for async response
  }

  // Custom URL Evaluation (On-demand URL Checker)
  if (message.type === 'ANALYZE_CUSTOM_URL') {
    try {
      const targetUrl = message.url || '';
      const analysis = analyzeUrl(targetUrl);
      const fallback = getVerdictAdvice(analysis.verdict, analysis.score, analysis.signals);
      sendResponse({
        ...analysis,
        plainExplanation: fallback.plainExplanation,
        advice: fallback.actionableSteps,
        source: 'rules-engine'
      });
    } catch (err) {
      sendResponse({ error: err.message });
    }
    return false;
  }

  // Deep Check request (DNS lookup + Apps Script / Gemini Explainer)
  if (message.type === 'RUN_DEEP_CHECK') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      let targetUrl = message.url;
      if (!targetUrl) {
        const activeTab = tabs[0];
        if (!activeTab || !activeTab.url) {
          sendResponse({ error: 'No active tab or URL specified' });
          return;
        }
        targetUrl = activeTab.url;
      }

      try {
        const url = new URL(targetUrl.startsWith('http') ? targetUrl : 'https://' + targetUrl);
        const host = url.hostname;

        // Extract base registrable domain for RDAP lookup
        const hostParts = host.split('.');
        const regDomain = hostParts.length >= 2 ? hostParts.slice(-2).join('.') : host;

        // 1. Query Google Public DNS over HTTPS (A records + MX records)
        let resolvedIps = [];
        let hasMxRecords = true;
        let mxCount = 0;
        let dnsStatus = 'NOERROR';

        try {
          const [aRes, mxRes] = await Promise.all([
            fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, {
              headers: { 'Accept': 'application/dns-json' }
            }).then(r => r.json()).catch(() => ({})),
            fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=MX`, {
              headers: { 'Accept': 'application/dns-json' }
            }).then(r => r.json()).catch(() => ({}))
          ]);

          if (aRes.Status === 3) dnsStatus = 'NXDOMAIN';
          else if (aRes.Status === 0) dnsStatus = 'NOERROR';

          resolvedIps = Array.isArray(aRes.Answer) 
            ? aRes.Answer.filter(rec => rec.type === 1).map(rec => rec.data) 
            : [];
          
          const mxAnswers = Array.isArray(mxRes.Answer) ? mxRes.Answer : [];
          hasMxRecords = mxAnswers.length > 0;
          mxCount = mxAnswers.length;
        } catch (dnsErr) {
          console.warn('[ScamLens DNS] Lookup error:', dnsErr);
        }

        // 2. Query ICANN / Verisign RDAP for Registration Age & Registrar
        let domainAgeDays = null;
        let createdDate = null;
        let registrarName = null;

        try {
          const isVerisign = regDomain.endsWith('.com') || regDomain.endsWith('.net');
          const rdapUrl = isVerisign
            ? `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(regDomain)}`
            : `https://rdap.org/domain/${encodeURIComponent(regDomain)}`;

          const rdapCtrl = new AbortController();
          const rdapTimeout = setTimeout(() => rdapCtrl.abort(), 3500);

          const rdapRes = await fetch(rdapUrl, {
            headers: { 'Accept': 'application/rdap+json, application/json' },
            signal: rdapCtrl.signal
          });
          clearTimeout(rdapTimeout);

          if (rdapRes.ok) {
            const rdapData = await rdapRes.json();
            const events = Array.isArray(rdapData.events) ? rdapData.events : [];
            const regEvent = events.find(e => e.eventAction === 'registration');
            if (regEvent && regEvent.eventDate) {
              createdDate = regEvent.eventDate;
              domainAgeDays = Math.floor((Date.now() - new Date(createdDate).getTime()) / (1000 * 60 * 60 * 24));
            }

            const entities = Array.isArray(rdapData.entities) ? rdapData.entities : [];
            const registrarEntity = entities.find(e => Array.isArray(e.roles) && e.roles.includes('registrar'));
            if (registrarEntity && registrarEntity.vcardArray) {
              const fn = registrarEntity.vcardArray[1]?.find(v => v[0] === 'fn');
              if (fn && fn[3]) registrarName = fn[3];
            }
          }
        } catch (rdapErr) {
          console.warn('[ScamLens RDAP] Lookup skipped/timed out:', rdapErr);
        }

        const externalSignals = {
          hasMxRecords,
          safeBrowsingMatch: false,
          domainAgeDays: domainAgeDays !== null ? domainAgeDays : undefined
        };

        // Tag external signals on the correct tab (match by URL, not just active tab)
        const allTabs = await chrome.tabs.query({});
        const urlMatchTab = allTabs.find(t => t.url && t.url.startsWith('http') && new URL(t.url).hostname === host) || activeTab;
        tabExternalSignals.set(urlMatchTab.id, externalSignals);
        const enriched = await evaluateTabScamLens(urlMatchTab.id, targetUrl);

        // 3. Query Google Apps Script Web App or Local Fallback Server for AI explanation
        const stored = await getStorage(['backendUrl', 'sharedToken', 'geminiApiKey']);
        // Fall back to .env build-time constants if nothing saved in storage
        const backendUrl   = stored.backendUrl   || (typeof __ENV__ !== 'undefined' ? __ENV__.BACKEND_URL    : '');
        const sharedToken  = stored.sharedToken  || (typeof __ENV__ !== 'undefined' ? __ENV__.SHARED_TOKEN   : 'scamlens-demo-token');
        const geminiApiKey = stored.geminiApiKey || (typeof __ENV__ !== 'undefined' ? __ENV__.GEMINI_API_KEY : '');
        
        const candidateEndpoints = [];
        if (backendUrl && backendUrl.trim()) {
          candidateEndpoints.push(backendUrl.trim());
        }
        candidateEndpoints.push('http://localhost:3000/api/check'); // local demo fallback

        let aiEnrichment = null;
        for (const endpoint of candidateEndpoints) {
          try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);

            const res = await fetch(endpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                token: sharedToken,
                url: activeTab.url,
                verdict: enriched.verdict,
                score: enriched.score,
                evidence: enriched.signals.map(s => s.evidence || s.label),
                apiKey: geminiApiKey,
                forceRefresh: Boolean(message.forceRefresh)
              }),
              signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (res.ok) {
              aiEnrichment = await res.json();
              break;
            }
          } catch (netErr) {}
        }

        if (aiEnrichment && aiEnrichment.plainExplanation) {
          enriched.plainExplanation = aiEnrichment.plainExplanation;
          if (aiEnrichment.advice) {
            enriched.advice = Array.isArray(aiEnrichment.advice) ? aiEnrichment.advice : [aiEnrichment.advice];
          }
          enriched.source = aiEnrichment.source || 'gemini';
          enriched.cached = Boolean(aiEnrichment.cached);
        } else {
          enriched.source = 'rules-engine';
        }

        // 4. Attach Structured Deep Check Intelligence Object
        enriched.deepCheck = {
          dns: {
            status: dnsStatus,
            ips: resolvedIps.slice(0, 4),
            hasMx: hasMxRecords,
            mxCount: mxCount
          },
          rdap: {
            domainAgeDays: domainAgeDays,
            created: createdDate ? new Date(createdDate).toISOString().split('T')[0] : 'N/A',
            registrar: registrarName || 'Standard / Privacy Guarded'
          },
          threatIntel: {
            isInfantDomain: domainAgeDays !== null && domainAgeDays < 30,
            safeBrowsing: 'Clean'
          }
        };

        tabVerdicts.set(activeTab.id, enriched);
        sendResponse(enriched);
      } catch (err) {
        sendResponse({ error: err.message });
      }
    });
    return true;
  }

  // Backend Connectivity Verification
  if (message.type === 'TEST_BACKEND_CONNECTION') {
    (async () => {
      const { url, token, geminiApiKey } = message;
      if (!url) {
        sendResponse({ success: false, error: 'No URL specified' });
        return;
      }
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        // Try health check GET first, then fallback to POST test
        const testRes = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: token || 'scamlens-demo-token',
            url: 'https://google.com',
            verdict: 'Safe',
            score: 0,
            evidence: ['Test ping'],
            apiKey: geminiApiKey
          }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (testRes.ok) {
          const data = await testRes.json();
          sendResponse({ success: true, data });
        } else {
          sendResponse({ success: false, status: testRes.status, error: `HTTP ${testRes.status}` });
        }
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // Shield toggling
  if (message.type === 'ENABLE_SHIELD') {
    (async () => {
      try {
        await enableShadowShield();
        await chrome.storage.local.set({ shieldActive: true });
        await recordShieldEvent(true);
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  if (message.type === 'DISABLE_SHIELD') {
    (async () => {
      try {
        await disableShadowShield();
        await chrome.storage.local.set({ shieldActive: false });
        await recordShieldEvent(false);
        sendResponse({ success: true });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  // Whitelist management
  if (message.type === 'CHECK_WHITELIST') {
    chrome.storage.local.get('whitelistedSites', (data) => {
      const sites = data.whitelistedSites || [];
      sendResponse({ isWhitelisted: sites.includes(message.domain) });
    });
    return true;
  }

  if (message.type === 'ADD_WHITELIST') {
    chrome.storage.local.get('whitelistedSites', async (data) => {
      const sites = data.whitelistedSites || [];
      if (!sites.includes(message.domain)) {
        sites.push(message.domain);
        await chrome.storage.local.set({ whitelistedSites: sites });
        enableShadowShield();
      }
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === 'REMOVE_WHITELIST') {
    chrome.storage.local.get('whitelistedSites', async (data) => {
      let sites = data.whitelistedSites || [];
      sites = sites.filter(s => s !== message.domain);
      await chrome.storage.local.set({ whitelistedSites: sites });
      enableShadowShield();
      sendResponse({ success: true });
    });
    return true;
  }

  // Detonate Nuke
  if (message.type === 'DETONATE_NUKE') {
    nukeSiteData(message.url).then(res => sendResponse(res));
    return true;
  }

  // Anti-fingerprinting telemetry event
  if (message.type === 'FINGERPRINT_ATTEMPT') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && tabs[0].url) {
        const domain = new URL(tabs[0].url).hostname;
        recordFingerprintAttempt(domain, message.detectionType, message.details);
      }
    });
  }
});

// ── Stats Store Utilities ──
function getDefaultDashboardStats() {
  return {
    totalBlocked: 0,
    totalDataSaved: 0,
    sessionsProtected: 0,
    cookiesCleaned: 0,
    totalMarketValue: 0,
    protectedDomains: [],
    weeklyData: {}
  };
}

function normalizeStats(stats = {}) {
  return {
    ...getDefaultDashboardStats(),
    ...stats,
    weeklyData: stats.weeklyData || {}
  };
}

function todayKey() {
  return new Date().toISOString().split('T')[0];
}

function ensureTodayBucket(stats) {
  const key = todayKey();
  if (!stats.weeklyData[key]) {
    stats.weeklyData[key] = { blocked: 0, dataSaved: 0, sessions: 0, cookies: 0, marketValue: 0 };
  }
}

async function ensureStatsInitialized() {
  const data = await getStorage(['dashboardStats', 'activityLog']);
  const normalized = normalizeStats(data.dashboardStats);
  ensureTodayBucket(normalized);
  await chrome.storage.local.set({
    dashboardStats: normalized,
    activityLog: Array.isArray(data.activityLog) ? data.activityLog : []
  });
}

function getStorage(keys) {
  return new Promise(resolve => chrome.storage.local.get(keys, resolve));
}

let blockQueue = 0;
let bytesQueue = 0;
let valueQueue = 0;
let blockTimeout = null;

async function recordBlockEvent(count, siteDomain, trackerDomain = null, resourceType = 'script') {
  if (count <= 0) return;

  const bytesSaved = TelemetryProcessor.estimateSavedBytes(resourceType) * count;
  const valueSaved = (count * 0.005);

  blockQueue += count;
  bytesQueue += bytesSaved;
  valueQueue += valueSaved;

  if (blockTimeout) return;

  blockTimeout = setTimeout(async () => {
    const currentCount = blockQueue;
    const currentBytes = bytesQueue;
    const currentValue = valueQueue;

    blockQueue = 0;
    bytesQueue = 0;
    valueQueue = 0;
    blockTimeout = null;

    await ensureStatsInitialized();
    const { dashboardStats = {}, activityLog = [] } = await getStorage(['dashboardStats', 'activityLog']);
    const stats = normalizeStats(dashboardStats);
    const key = todayKey();
    ensureTodayBucket(stats);

    stats.totalBlocked += currentCount;
    stats.totalDataSaved += currentBytes;
    stats.totalMarketValue = (stats.totalMarketValue || 0) + currentValue;
    stats.weeklyData[key].blocked += currentCount;
    stats.weeklyData[key].dataSaved += currentBytes;
    stats.weeklyData[key].marketValue = (stats.weeklyData[key].marketValue || 0) + currentValue;

    const newEntry = {
      type: 'block',
      category: 'advertising',
      message: `Blocked ${currentCount} tracker request${currentCount > 1 ? 's' : ''} on ${siteDomain}`,
      domain: trackerDomain,
      timestamp: Date.now()
    };

    const updatedLog = [newEntry, ...activityLog].slice(0, 100);

    await chrome.storage.local.set({
      dashboardStats: stats,
      activityLog: updatedLog
    });
  }, 100);
}

async function recordCookieClean(count, domain) {
  if (count <= 0) return;
  await ensureStatsInitialized();
  const { dashboardStats = {}, activityLog = [] } = await getStorage(['dashboardStats', 'activityLog']);
  const stats = normalizeStats(dashboardStats);
  const key = todayKey();
  ensureTodayBucket(stats);

  stats.cookiesCleaned += count;
  stats.weeklyData[key].cookies = (stats.weeklyData[key].cookies || 0) + count;
  const cookieVal = count * 0.05;
  stats.totalMarketValue = (stats.totalMarketValue || 0) + cookieVal;

  const newEntry = {
    type: 'clean',
    message: `Cleaned ${count} tracking artifact${count > 1 ? 's' : ''} from ${domain}`,
    timestamp: Date.now()
  };

  const updatedLog = [newEntry, ...activityLog].slice(0, 100);
  await chrome.storage.local.set({ dashboardStats: stats, activityLog: updatedLog });
}

async function recordShieldEvent(enabled) {
  const { activityLog = [] } = await getStorage('activityLog');
  const newEntry = {
    type: 'shield',
    message: enabled ? 'Safety Shield Activated — blocking trackers' : 'Safety Shield Deactivated',
    timestamp: Date.now()
  };
  const updatedLog = [newEntry, ...activityLog].slice(0, 100);
  await chrome.storage.local.set({ activityLog: updatedLog });
}

async function recordFingerprintAttempt(siteDomain, type, details) {
  const { activityLog = [] } = await getStorage('activityLog');
  const newEntry = {
    type: 'fingerprint',
    message: `Prevented ${type} fingerprinting on ${siteDomain}`,
    details,
    timestamp: Date.now()
  };
  const updatedLog = [newEntry, ...activityLog].slice(0, 100);
  await chrome.storage.local.set({ activityLog: updatedLog });
}
