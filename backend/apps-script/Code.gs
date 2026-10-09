/**
 * ScamLens — Google Apps Script Backend
 * Problem Statement 3: AI-Powered Cybersecurity & Digital Safety
 * 
 * Strict Principle: "Rules decide. AI explains."
 * Verdicts and scores are strictly deterministic. Gemini is used solely to
 * translate technical security evidence into plain, non-jargon guidance.
 */

// Default demo token (can be overridden via Script Properties: SHARED_TOKEN)
const DEFAULT_DEMO_TOKEN = 'scamlens-demo-token';

/**
 * HTTP POST Handler for ScamLens Web App
 */
function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return jsonResponse({ error: 'Missing request body' }, 400);
    }

    const payload = JSON.parse(e.postData.contents);
    const {
      token,
      url,
      signals = {},
      verdict = 'Safe',
      score = 0,
      evidence = [],
      model = 'gemini-1.5-flash',
      forceRefresh = false
    } = payload;

    // Verify token
    const scriptProps = PropertiesService.getScriptProperties();
    const configuredToken = scriptProps.getProperty('SHARED_TOKEN') || DEFAULT_DEMO_TOKEN;
    if (token && token !== configuredToken && configuredToken !== '') {
      return jsonResponse({ error: 'Unauthorized: Invalid token' }, 401);
    }

    if (!url) {
      return jsonResponse({ error: 'Missing "url" parameter' }, 400);
    }

    // Cache lookup
    const cache = CacheService.getScriptCache();
    const cacheKey = 'scamlens_' + Utilities.base64EncodeWebSafe(url.substring(0, 100));
    
    if (!forceRefresh) {
      const cachedResult = cache.get(cacheKey);
      if (cachedResult) {
        try {
          const parsed = JSON.parse(cachedResult);
          parsed.cached = true;
          return jsonResponse(parsed, 200);
        } catch (err) {}
      }
    }

    // Check Google Safe Browsing if API key configured
    let safeBrowsingMatch = false;
    const safeBrowsingKey = scriptProps.getProperty('SAFE_BROWSING_API_KEY');
    if (safeBrowsingKey) {
      safeBrowsingMatch = checkSafeBrowsing(url, safeBrowsingKey);
    }

    // Compute or respect deterministic verdict
    let finalVerdict = verdict;
    let finalScore = score;
    let finalEvidence = [...evidence];

    if (safeBrowsingMatch && !finalEvidence.includes('Google Safe Browsing flagged as malicious threat')) {
      finalVerdict = 'Dangerous';
      finalScore = 100;
      finalEvidence.unshift('Google Safe Browsing flagged as malicious threat');
    }

    // Get plain explanation: Try Gemini first, fallback to template
    const geminiKey = scriptProps.getProperty('GEMINI_API_KEY');
    let aiExplanation = null;
    let source = 'template';

    if (geminiKey) {
      aiExplanation = callGeminiExplainer(url, finalVerdict, finalScore, finalEvidence, geminiKey, model);
      if (aiExplanation && aiExplanation.plainExplanation) {
        source = 'gemini';
      }
    }

    // Deterministic fallback if Gemini unavailable or not configured
    if (!aiExplanation || !aiExplanation.plainExplanation) {
      aiExplanation = getFallbackTemplate(finalVerdict, finalScore, finalEvidence);
      source = 'template';
    }

    const responsePayload = {
      url: url,
      verdict: finalVerdict,
      score: finalScore,
      evidence: finalEvidence,
      plainExplanation: aiExplanation.plainExplanation,
      advice: aiExplanation.advice,
      cached: false,
      source: source,
      timestamp: new Date().toISOString()
    };

    // Cache successful evaluation for 6 hours (21600 seconds)
    try {
      cache.put(cacheKey, JSON.stringify(responsePayload), 21600);
    } catch (cacheErr) {
      console.warn('Cache write failed:', cacheErr);
    }

    return jsonResponse(responsePayload, 200);

  } catch (err) {
    return jsonResponse({
      error: 'Backend evaluation error: ' + err.message,
      verdict: 'Suspicious',
      score: 50,
      evidence: ['Backend evaluation encountered an error'],
      plainExplanation: 'We were unable to fully evaluate this page due to a temporary service error.',
      advice: 'Exercise caution and verify the URL manually before entering any information.',
      source: 'error-fallback'
    }, 500);
  }
}

/**
 * HTTP GET Handler for health check and connectivity verification
 */
function doGet(e) {
  return jsonResponse({
    status: 'ok',
    service: 'ScamLens Backend',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    geminiConfigured: !!PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY'),
    safeBrowsingConfigured: !!PropertiesService.getScriptProperties().getProperty('SAFE_BROWSING_API_KEY')
  }, 200);
}

/**
 * Call Gemini 1.5/2.0 Flash via Google AI Studio API
 * STRICT RULE: Gemini only explains; it NEVER alters verdicts or scores.
 */
function callGeminiExplainer(url, verdict, score, evidence, apiKey, modelName) {
  try {
    const activeModel = modelName || 'gemini-1.5-flash';
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(activeModel)}:generateContent?key=${apiKey}`;

    const systemPrompt = `You are ScamLens AI Safety Explainer. You NEVER determine, compute, or change threat verdicts or risk scores.
A deterministic security engine evaluated the following website:
URL: ${url}
Deterministic Verdict: ${verdict}
Risk Score: ${score}/100
Technical Evidence: ${evidence.length > 0 ? evidence.join('; ') : 'No suspicious anomalies detected.'}

Your sole task: Translate the technical evidence into two empathetic, clear, non-technical sentences for an everyday non-technical user.
Sentence 1 (plainExplanation): Explain clearly what this site is or what threat it represents without cybersecurity jargon.
Sentence 2 (advice): Tell the user the single immediate action they should take.

Respond ONLY with valid JSON conforming to this schema:
{
  "plainExplanation": "string",
  "advice": "string"
}`;

    const requestBody = {
      contents: [{
        parts: [{ text: systemPrompt }]
      }],
      generationConfig: {
        temperature: 0.2,
        topK: 20,
        topP: 0.8,
        responseMimeType: "application/json"
      }
    };

    const options = {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify(requestBody),
      muteHttpExceptions: true
    };

    const response = UrlFetchApp.fetch(endpoint, options);
    const code = response.getResponseCode();

    if (code !== 200) {
      console.warn(`Gemini API returned HTTP ${code}: ${response.getContentText()}`);
      return null;
    }

    const resJson = JSON.parse(response.getContentText());
    const candidateText = resJson.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!candidateText) return null;

    const parsedOutput = JSON.parse(candidateText.trim());
    return {
      plainExplanation: parsedOutput.plainExplanation,
      advice: parsedOutput.advice
    };
  } catch (err) {
    console.warn('Gemini call failed:', err);
    return null;
  }
}

/**
 * Deterministic template explanations for offline fallback
 */
function getFallbackTemplate(verdict, score, evidence) {
  if (verdict === 'Dangerous') {
    let explanation = 'This website displays critical security threats typical of active phishing or impersonation scams.';
    if (evidence.some(e => e.includes('credential') || e.includes('password'))) {
      explanation = 'This website appears to be an unauthorized copy designed to steal your passwords or personal data.';
    } else if (evidence.some(e => e.includes('Safe Browsing'))) {
      explanation = 'Google Safe Browsing has confirmed this web page as a known malicious deceptive site.';
    }
    return {
      plainExplanation: explanation,
      advice: 'Do not enter passwords, payment numbers, or personal info. Close this tab immediately.'
    };
  }

  if (verdict === 'Suspicious') {
    let explanation = 'This site exhibits several warning signs such as mismatched domain names or unverified hosting.';
    if (evidence.some(e => e.includes('look-alike') || e.includes('impersonation'))) {
      explanation = 'The website address closely mimics a well-known brand, which is a common tactic used in phishing.';
    }
    return {
      plainExplanation: explanation,
      advice: 'Verify the web address carefully before proceeding. Do not provide sensitive personal or financial credentials.'
    };
  }

  return {
    plainExplanation: 'No deceptive domain patterns or suspicious forms were detected on this web page.',
    advice: 'This site appears standard. Always maintain standard browsing precautions.'
  };
}

/**
 * Google Safe Browsing Lookup v4 Check
 */
function checkSafeBrowsing(url, apiKey) {
  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    const payload = {
      client: {
        clientId: "scamlens-apps-script",
        clientVersion: "1.0.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: url }]
      }
    };

    const options = {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    };

    const res = UrlFetchApp.fetch(endpoint, options);
    if (res.getResponseCode() === 200) {
      const data = JSON.parse(res.getContentText());
      return !!(data.matches && data.matches.length > 0);
    }
  } catch (err) {
    console.warn('Safe Browsing check error:', err);
  }
  return false;
}

/**
 * Helper to return standard JSON HTTP response
 */
function jsonResponse(data, statusCode) {
  return ContentService.createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}
