/**
 * ScamLens Shared Rules Engine (rules.js)
 * "Rules decide. AI explains."
 * 
 * Pure JavaScript, zero dependencies, no browser or Node APIs.
 * Deterministic detection for phishing, malicious URLs, and suspicious page signals.
 */

// ── Bundled Popular Allowlist (Tranco Top Sites Subset) ──
export const POPULAR_DOMAINS = new Set([
  'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'apple.com',
  'microsoft.com', 'wikipedia.org', 'twitter.com', 'x.com', 'instagram.com',
  'linkedin.com', 'github.com', 'netflix.com', 'paypal.com', 'reddit.com',
  'whatsapp.com', 'zoom.us', 'bing.com', 'yahoo.com', 'ebay.com',
  'cloudflare.com', 'wordpress.org', 'adobe.com', 'spotify.com', 'twitch.tv',
  'dropbox.com', 'salesforce.com', 'craigslist.org', 'medium.com', 'nytimes.com',
  'bbc.com', 'cnn.com', 'espn.com', 'weather.com', 'live.com', 'office.com',
  'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'paytm.com', 'irctc.co.in',
  'google.co.in', 'amazon.in', 'flipkart.com', 'canva.com', 'notion.so'
]);

// ── Bundled High-Target Brand Keywords ──
export const TARGET_BRANDS = [
  'google', 'paypal', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook',
  'instagram', 'whatsapp', 'twitter', 'chase', 'wellsfargo', 'bankofamerica',
  'sbi', 'hdfc', 'icici', 'paytm', 'binance', 'coinbase', 'github',
  'linkedin', 'dropbox', 'adobe', 'steam', 'spotify', 'telegram', 'snapchat',
  'flipkart', 'citibank', 'yahoo', 'outlook', 'metamask', 'barclays'
];

// ── Bundled Heavily Abused TLDs ──
export const SUSPICIOUS_TLDS = new Set([
  'top', 'xyz', 'work', 'click', 'buzz', 'loan', 'fit', 'gq', 'cf', 'ml', 'tk',
  'zip', 'mov', 'quest', 'rest', 'cam', 'country', 'stream', 'icu', 'kim',
  'party', 'racing', 'surf', 'bar', 'live', 'download', 'support'
]);

// ── Urgency & Fraud Action Keywords ──
export const URGENCY_PHRASES = [
  'verify account', 'verify your account', 'urgent action', 'immediate action',
  'account suspended', 'account blocked', 'unauthorized login', 'security alert',
  'one-time password', 'otp required', 'enter otp', 'payment failed',
  'update billing', 'confirm identity', 'limited time', 'prize winner',
  'claim reward', 'tax refund', 'kyc update', 'pan verification', 'aadhaar verify'
];

// ── Multi-Part TLDs for Registrable Domain Extraction ──
const TWO_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
  'co.in', 'org.in', 'net.in', 'gov.in', 'ac.in',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'com.br', 'com.cn', 'co.jp', 'co.kr', 'com.sg',
  'com.mx', 'co.za', 'com.tr', 'com.tw'
]);

/**
 * Extracts normalized hostname and protocol safely from input
 * @param {string} input 
 * @returns {{ host: string, protocol: string, pathname: string, fullUrl: string } | null}
 */
export function parseUrlSafely(input) {
  if (!input || typeof input !== 'string') return null;
  let str = input.trim();
  if (!str) return null;

  // Add https:// scheme if bare domain provided
  if (!/^https?:\/\//i.test(str)) {
    str = 'https://' + str;
  }

  try {
    const parsed = new URL(str);
    const host = parsed.hostname.toLowerCase().replace(/^\.+|\.+$/g, '');
    return {
      host,
      protocol: parsed.protocol.toLowerCase(),
      pathname: parsed.pathname,
      search: parsed.search,
      fullUrl: parsed.href
    };
  } catch (err) {
    return null;
  }
}

/**
 * Extracts registrable domain (eTLD + 1)
 * e.g., 'sub.login.example.com' -> 'example.com'
 * e.g., 'portal.sbi.co.in' -> 'sbi.co.in'
 * @param {string} host 
 * @returns {string}
 */
export function getRegistrableDomain(host) {
  if (!host) return '';
  const parts = host.split('.');
  if (parts.length <= 2) return host;

  const lastTwo = parts.slice(-2).join('.');
  if (TWO_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Computes Levenshtein edit distance between two strings
 * @param {string} a 
 * @param {string} b 
 * @returns {number}
 */
export function levenshteinDistance(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  const row = [];
  for (let i = 0; i <= b.length; i++) row[i] = i;

  for (let i = 1; i <= a.length; i++) {
    let prev = i;
    for (let j = 1; j <= b.length; j++) {
      let val;
      if (a[i - 1] === b[j - 1]) {
        val = row[j - 1];
      } else {
        val = Math.min(row[j - 1] + 1, prev + 1, row[j] + 1);
      }
      row[j - 1] = prev;
      prev = val;
    }
    row[b.length] = prev;
  }
  return row[b.length];
}

/**
 * Checks if a string is a valid IPv4 address literal
 * @param {string} host 
 * @returns {boolean}
 */
export function isIPv4Literal(host) {
  if (!host) return false;
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  return parts.every(part => {
    if (!/^\d+$/.test(part)) return false;
    const n = parseInt(part, 10);
    return n >= 0 && n <= 255 && (part === '0' || !part.startsWith('0'));
  });
}

/**
 * Checks if a string is an IPv6 address literal
 * @param {string} host 
 * @returns {boolean}
 */
export function isIPv6Literal(host) {
  if (!host) return false;
  const clean = host.replace(/^\[|\]$/g, '');
  return clean.includes(':') && /^[0-9a-fA-F:]+$/.test(clean);
}

/**
 * Checks if hostname contains Punycode or mixed-script / non-standard Unicode homoglyphs
 * @param {string} host 
 * @returns {boolean}
 */
export function hasHomographOrPunycode(host) {
  if (!host) return false;
  if (host.includes('xn--')) return true;
  // Non-ASCII character check (Unicode spoofing)
  if (/[^\x00-\x7F]/.test(host)) return true;
  return false;
}

/**
 * Evaluates brand look-alike characteristics
 * @param {string} host 
 * @param {string} registrableDomain 
 * @param {string} pathname 
 * @returns {{ isLookalike: boolean, brand: string, reason: string } | null}
 */
export function checkBrandLookalike(host, registrableDomain, pathname = '') {
  if (!host || !registrableDomain) return null;

  const domainBase = registrableDomain.split('.')[0];
  const baseTokens = domainBase.split('-');

  // 1. Direct fuzzy edit distance or compound token matching
  for (const brand of TARGET_BRANDS) {
    if (domainBase === brand) continue; // Legitimate exact brand base

    // Direct edit distance on whole base
    const dist = levenshteinDistance(domainBase, brand);
    if (dist === 1 || (dist === 2 && brand.length >= 6 && Math.abs(domainBase.length - brand.length) <= 1)) {
      return {
        isLookalike: true,
        brand,
        reason: `Domain base "${domainBase}" is visually deceptive look-alike of trusted brand "${brand}" (edit distance: ${dist})`
      };
    }

    // Compound domain tokens (e.g. netflix-billing, sbi-portal, micros0ft-support)
    if (baseTokens.length > 1) {
      for (const token of baseTokens) {
        if (!token) continue;
        if (token === brand) {
          return {
            isLookalike: true,
            brand,
            reason: `Trusted brand name "${brand}" used in compound domain "${registrableDomain}"`
          };
        }
        const tokenDist = levenshteinDistance(token, brand);
        if (tokenDist === 1 || (tokenDist === 2 && brand.length >= 6 && Math.abs(token.length - brand.length) <= 1)) {
          return {
            isLookalike: true,
            brand,
            reason: `Compound domain token "${token}" is deceptive look-alike of trusted brand "${brand}" (edit distance: ${tokenDist})`
          };
        }
      }
    }
  }

  // 2. Brand name buried in subdomain or path on an untrusted registrable domain
  for (const brand of TARGET_BRANDS) {
    if (domainBase === brand) continue;

    // Check subdomains (e.g. paypal.com.login-verify.net)
    const subdomains = host.slice(0, host.length - registrableDomain.length).replace(/\.+$/, '');
    if (subdomains) {
      const subParts = subdomains.split(/[.-]/);
      if (subParts.some(p => p === brand)) {
        return {
          isLookalike: true,
          brand,
          reason: `Trusted brand name "${brand}" spoofed in subdomain, but registered domain is "${registrableDomain}"`
        };
      }
    }

    // Check path (e.g. secure-portal.org/paypal/login)
    if (pathname) {
      const pathParts = pathname.toLowerCase().split('/');
      if (pathParts.some(p => p === brand)) {
        return {
          isLookalike: true,
          brand,
          reason: `Trusted brand name "${brand}" mimics official portal in URL path on foreign domain "${registrableDomain}"`
        };
      }
    }
  }

  return null;
}

/**
 * Main Deterministic Rules Evaluation
 * 
 * @param {string} urlInput The URL or hostname to inspect
 * @param {Object} [pageSignals] In-page DOM signals collected by content script
 * @param {boolean} [pageSignals.passwordForm] Does page have a password / payment form
 * @param {string} [pageSignals.formTargetHost] Hostname the credential form submits to
 * @param {string[]} [pageSignals.keywordHits] Urgency / OTP keywords found in page text
 * @param {Object} [externalSignals] Enrichment from backend lookups
 * @param {boolean} [externalSignals.safeBrowsingMatch] Threat match from Safe Browsing
 * @param {number} [externalSignals.domainAgeDays] Domain age in days from RDAP
 * @param {boolean} [externalSignals.hasMxRecords] Has MX records in DNS
 * @returns {Object} Verdict, score, signals, evidence, advice, and explanation
 */
export function analyzeUrl(urlInput, pageSignals = {}, externalSignals = {}) {
  const parsed = parseUrlSafely(urlInput);

  if (!parsed) {
    return {
      verdict: 'Suspicious',
      score: 45,
      confidence: 'low',
      host: '',
      signals: [{
        id: 'malformed_url',
        label: 'Malformed or unparseable URL',
        points: 45,
        evidence: 'The supplied target could not be parsed into a standard web address format.'
      }],
      evidence: ['Malformed or invalid web URL format'],
      advice: [
        'Do not open this link or paste sensitive details.',
        'Verify the source that sent you this address.'
      ],
      explanation: 'ScamLens could not safely parse this web address. Unparseable URL formats are frequently used to obfuscate destination endpoints.',
      mode: 'offline',
      explanationSource: 'template'
    };
  }

  const { host, protocol, pathname, fullUrl } = parsed;
  const registrableDomain = getRegistrableDomain(host);
  const isAllowlisted = POPULAR_DOMAINS.has(host) || POPULAR_DOMAINS.has(registrableDomain);

  const signals = [];
  let score = 0;
  let hardSignalFired = false;

  // ── Signal 1: Safe Browsing Match (External Override) ──
  if (externalSignals.safeBrowsingMatch) {
    hardSignalFired = true;
    signals.push({
      id: 'safe_browsing_match',
      label: 'Known Malicious URL (Google Safe Browsing)',
      points: 100,
      evidence: 'Google Safe Browsing threat lists identify this destination as an active malware or phishing threat.'
    });
    score += 100;
  }

  // ── Signal 2: Raw IP Address Host (30 pts, Local) ──
  if (isIPv4Literal(host) || isIPv6Literal(host)) {
    hardSignalFired = true;
    signals.push({
      id: 'raw_ip_host',
      label: 'Direct IP address destination',
      points: 30,
      evidence: `The link routes directly to numerical IP literal "${host}" instead of a registered domain name.`
    });
    score += 30;
  }

  // ── Signal 3: Punycode / IDN Homograph (25 pts, Local) ──
  if (hasHomographOrPunycode(host)) {
    signals.push({
      id: 'punycode_homograph',
      label: 'Internationalized homograph / Punycode detected',
      points: 25,
      evidence: `Hostname contains Punycode ("xn--") or mixed non-ASCII scripts designed to visually impersonate other characters.`
    });
    score += 25;
  }

  // ── Signal 4: Brand Look-Alike / Impersonation (35 pts, Local) ──
  const lookalike = checkBrandLookalike(host, registrableDomain, pathname);
  if (lookalike && !isAllowlisted) {
    signals.push({
      id: 'brand_lookalike',
      label: `Brand look-alike (${lookalike.brand})`,
      points: 35,
      evidence: lookalike.reason
    });
    score += 35;
  }

  // ── Signal 5: Suspicious Top-Level Domain (10 pts, Local) ──
  const tld = host.split('.').pop();
  if (SUSPICIOUS_TLDS.has(tld) && !isAllowlisted) {
    signals.push({
      id: 'suspicious_tld',
      label: `Heavily abused TLD (.${tld})`,
      points: 10,
      evidence: `Top-level domain ".${tld}" has a statistically high correlation with disposable scam and spam campaigns.`
    });
    score += 10;
  }

  // ── Signal 6: Structure Oddities (10 pts, Local) ──
  const subdomains = host.slice(0, host.length - registrableDomain.length).replace(/\.+$/, '');
  const subdomainCount = subdomains ? subdomains.split('.').length : 0;
  const hyphenCount = (host.match(/-/g) || []).length;
  const hasAtSymbol = fullUrl.includes('@');
  const isOverlyLong = host.length > 45;

  if (hasAtSymbol || subdomainCount >= 4 || isOverlyLong || hyphenCount >= 3) {
    const reasons = [];
    if (hasAtSymbol) reasons.push('contains "@" symbol to trick browser parsing');
    if (subdomainCount >= 4) reasons.push(`excessive subdomain depth (${subdomainCount} levels)`);
    if (isOverlyLong) reasons.push(`excessive hostname length (${host.length} characters)`);
    if (hyphenCount >= 3) reasons.push(`multiple hyphens (${hyphenCount}) masking destination`);

    signals.push({
      id: 'structure_oddities',
      label: 'Anomalous URL structure',
      points: 10,
      evidence: `URL exhibits deceptive structure: ${reasons.join(', ')}.`
    });
    score += 10;
  }

  // ── Signal 7: Unencrypted HTTP (15 pts, Local) ──
  if (protocol === 'http:') {
    signals.push({
      id: 'no_https',
      label: 'Unencrypted connection (HTTP)',
      points: 15,
      evidence: 'Site does not use HTTPS encryption; connection can be intercepted or altered in transit.'
    });
    score += 15;
  }

  // ── Signal 8: Credential Form to External Domain (30 pts, DOM signal) ──
  if (pageSignals.passwordForm && pageSignals.formTargetHost) {
    const targetReg = getRegistrableDomain(pageSignals.formTargetHost.toLowerCase());
    if (targetReg && targetReg !== registrableDomain) {
      hardSignalFired = true;
      signals.push({
        id: 'form_cross_domain',
        label: 'Cross-domain credential form',
        points: 30,
        evidence: `Credential form on "${host}" posts sensitive input directly to a different domain "${targetReg}".`
      });
      score += 30;
    }
  }

  // ── Signal 9: Urgency / Fraud Keywords (10 pts, DOM signal) ──
  if (Array.isArray(pageSignals.keywordHits) && pageSignals.keywordHits.length > 0) {
    signals.push({
      id: 'urgency_language',
      label: 'High-pressure / OTP keyword patterns',
      points: 10,
      evidence: `Page text prominently features high-urgency keywords: ${pageSignals.keywordHits.slice(0, 3).map(k => `"${k}"`).join(', ')}.`
    });
    score += 10;
  }

  // ── Signal 10: Newly Registered Domain (25 pts, RDAP backend signal) ──
  if (typeof externalSignals.domainAgeDays === 'number' && externalSignals.domainAgeDays < 30) {
    signals.push({
      id: 'new_domain',
      label: `Newly registered domain (${externalSignals.domainAgeDays} days old)`,
      points: 25,
      evidence: `Domain was created ${externalSignals.domainAgeDays} days ago; infant domains carry high fraud prevalence.`
    });
    score += 25;
  }

  // ── Signal 11: Weak DNS on Lookalike (5 pts, DNS backend signal) ──
  if (lookalike && externalSignals.hasMxRecords === false) {
    signals.push({
      id: 'weak_dns_hygiene',
      label: 'Missing mail exchange (MX) records',
      points: 5,
      evidence: `Brand look-alike host has no valid MX records configured, typical of burner phishing domains.`
    });
    score += 5;
  }

  // ── Cap Score at 100 ──
  score = Math.min(100, score);

  // ── Popular Domain Allowlist Rule ──
  // Popular domains cap verdict at Safe unless a hard signal (raw IP, cross-domain password form, known malware) fired
  if (isAllowlisted && !hardSignalFired) {
    score = Math.min(20, score);
  }

  // ── Verdict Classification ──
  let verdict = 'Safe';
  if (externalSignals.safeBrowsingMatch || score >= 60) {
    verdict = 'Dangerous';
  } else if (score >= 30) {
    verdict = 'Suspicious';
  } else {
    verdict = 'Safe';
  }

  // ── Confidence Estimation ──
  let confidence = 'high';
  if (signals.length === 0) {
    confidence = isAllowlisted ? 'high' : 'medium';
  } else if (signals.length === 1 && score < 30) {
    confidence = 'medium';
  }

  // ── Deterministic Actionable Advice & Friendly Explanation ──
  const advice = generateAdvice(verdict, signals, host);
  const explanation = generateTemplateExplanation(verdict, score, signals, host, isAllowlisted);

  return {
    url: fullUrl,
    host,
    registrableDomain,
    verdict,
    score,
    confidence,
    signals,
    evidence: signals.map(s => s.evidence),
    advice,
    explanation,
    isAllowlisted,
    mode: Object.keys(externalSignals).length > 0 ? 'online' : 'offline',
    explanationSource: 'template'
  };
}

/**
 * Generates user-actionable advice based on verdict & triggered signals
 * @param {'Safe' | 'Suspicious' | 'Dangerous'} verdict 
 * @param {Array} signals 
 * @param {string} host 
 * @returns {string[]}
 */
function generateAdvice(verdict, signals, host) {
  if (verdict === 'Dangerous') {
    const list = [
      'Do not enter any passwords, credit card numbers, or OTP codes.',
      'Do not download or open any attachments or installers from this page.'
    ];
    if (signals.some(s => s.id === 'brand_lookalike')) {
      list.push(`If you intended to reach a service like ${signals.find(s => s.id === 'brand_lookalike').label.replace('Brand look-alike (', '').replace(')', '')}, type the official website address directly into your browser.`);
    } else {
      list.push('Close this tab and do not interact with the page contents.');
    }
    return list;
  }

  if (verdict === 'Suspicious') {
    const list = [
      'Inspect the browser address bar carefully for typos or unusual domain extensions.',
      'Do not submit verification forms or OTP codes through links received via SMS, email, or chat.'
    ];
    if (signals.some(s => s.id === 'no_https')) {
      list.push('Avoid transmitting any personal data over unencrypted HTTP connections.');
    } else {
      list.push('Navigate to the company’s official homepage independently if in doubt.');
    }
    return list;
  }

  return [
    'No brand spoofing or known deceptive patterns detected on this address.',
    'Continue browsing normally, while remaining mindful of standard security practices.'
  ];
}

/**
 * Deterministic explanation builder ("Rules decide. AI explains.")
 * Serves as reliable offline text & baseline fallback when LLM is unavailable.
 */
function generateTemplateExplanation(verdict, score, signals, host, isAllowlisted) {
  if (verdict === 'Dangerous') {
    if (signals.some(s => s.id === 'safe_browsing_match')) {
      return `Warning: ${host} is flagged on global cybersecurity threat intelligence databases as a malicious destination. Navigating this site poses an immediate risk of credential theft or malware infection.`;
    }
    if (signals.some(s => s.id === 'form_cross_domain')) {
      return `Critical risk: This webpage attempts to capture login credentials and send them to an external third-party domain. This is a hallmark technique of phishing portals.`;
    }
    if (signals.some(s => s.id === 'brand_lookalike')) {
      return `Critical risk: ${host} is actively impersonating a trusted brand using a deceptive look-alike domain. Entering credentials or payment information here will compromise your account.`;
    }
    return `Critical risk: Multiple high-severity warning indicators were detected on ${host} (Score: ${score}/100). This page displays characteristics strongly associated with fraudulent campaigns.`;
  }

  if (verdict === 'Suspicious') {
    const topLabels = signals.slice(0, 2).map(s => s.label.toLowerCase()).join(' and ');
    return `Caution recommended: ScamLens detected potential risk factors on ${host} (${topLabels}). While not definitively blocked, the site deviates from standard security standards.`;
  }

  if (isAllowlisted) {
    return `${host} is a verified popular domain with no anomalous structure or deceptive form targets detected.`;
  }

  return `No deceptive signals, brand mimicry, or high-risk indicators were detected for ${host}.`;
}
