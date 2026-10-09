/**
 * ScamLens — Local Fallback Server
 * Problem Statement 3: AI-Powered Cybersecurity & Digital Safety
 * 
 * Standalone, zero-dependency Node.js HTTP server implementing the exact same
 * API contract as the Google Apps Script Web App.
 * 
 * Usage:
 *   node backend/server.js
 * Or:
 *   $env:GEMINI_API_KEY="your-key"; node backend/server.js
 */

import http from 'node:http';
import https from 'node:https';

const PORT = Number(process.env.PORT) || 3000;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const SHARED_TOKEN = process.env.SHARED_TOKEN || 'scamlens-demo-token';

// In-memory cache for demo
const analysisCache = new Map();

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With'
  });
  res.end(JSON.stringify(data));
}

function handleOptions(res) {
  res.writeHead(204, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    'Access-Control-Max-Age': '86400'
  });
  res.end();
}

/**
 * Deterministic template explanation matching rules.js
 */
function getTemplateAdvice(verdict, score, evidence) {
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
    let explanation = 'This site exhibits warning signs such as mismatched domain names or unverified hosting.';
    if (evidence.some(e => e.includes('look-alike') || e.includes('impersonation'))) {
      explanation = 'The website address closely mimics a well-known brand, which is a common tactic used in phishing.';
    }
    return {
      plainExplanation: explanation,
      advice: 'Verify the web address carefully before proceeding. Do not provide sensitive credentials.'
    };
  }

  return {
    plainExplanation: 'No deceptive domain patterns or suspicious forms were detected on this web page.',
    advice: 'This site appears standard. Always maintain standard browsing precautions.'
  };
}

/**
 * Call Gemini Flash API
 */
async function callGemini(url, verdict, score, evidence, apiKey, model = 'gemini-1.5-flash') {
  if (!apiKey) return null;

  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${apiKey}`;
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

  const bodyData = JSON.stringify({
    contents: [{ parts: [{ text: systemPrompt }] }],
    generationConfig: {
      temperature: 0.2,
      responseMimeType: "application/json"
    }
  });

  return new Promise((resolve) => {
    try {
      const parsedUrl = new URL(endpoint);
      const req = https.request({
        hostname: parsedUrl.hostname,
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyData)
        },
        timeout: 6000
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode !== 200) {
            console.warn(`[Gemini Error] HTTP ${res.statusCode}: ${data}`);
            return resolve(null);
          }
          try {
            const parsed = JSON.parse(data);
            const text = parsed.candidates?.[0]?.content?.parts?.[0]?.text;
            if (!text) return resolve(null);
            const jsonResult = JSON.parse(text.trim());
            resolve(jsonResult);
          } catch (e) {
            resolve(null);
          }
        });
      });

      req.on('error', (err) => {
        console.warn('[Gemini Request Error]', err.message);
        resolve(null);
      });
      req.on('timeout', () => {
        req.destroy();
        resolve(null);
      });

      req.write(bodyData);
      req.end();
    } catch (e) {
      resolve(null);
    }
  });
}

const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    return handleOptions(res);
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Health check
  if (req.method === 'GET' && (parsedUrl.pathname === '/' || parsedUrl.pathname === '/api/health')) {
    return sendJson(res, 200, {
      status: 'ok',
      service: 'ScamLens Local Fallback Server',
      version: '1.0.0',
      port: PORT,
      geminiConfigured: !!GEMINI_API_KEY,
      timestamp: new Date().toISOString()
    });
  }

  // Check endpoint
  if (req.method === 'POST' && (parsedUrl.pathname === '/api/check' || parsedUrl.pathname === '/')) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body || '{}');
        const {
          token,
          url,
          verdict = 'Safe',
          score = 0,
          evidence = [],
          model = 'gemini-1.5-flash',
          forceRefresh = false
        } = payload;

        if (token && token !== SHARED_TOKEN && SHARED_TOKEN !== '') {
          return sendJson(res, 401, { error: 'Unauthorized token' });
        }

        if (!url) {
          return sendJson(res, 400, { error: 'Missing url in payload' });
        }

        // Cache check
        if (!forceRefresh && analysisCache.has(url)) {
          const cached = analysisCache.get(url);
          return sendJson(res, 200, { ...cached, cached: true });
        }

        // Gemini AI Explainer call with template fallback
        let source = 'template';
        let explanationObj = null;

        const effectiveKey = process.env.GEMINI_API_KEY || payload.apiKey;
        if (effectiveKey) {
          explanationObj = await callGemini(url, verdict, score, evidence, effectiveKey, model);
          if (explanationObj && explanationObj.plainExplanation) {
            source = 'gemini';
          }
        }

        if (!explanationObj || !explanationObj.plainExplanation) {
          explanationObj = getTemplateAdvice(verdict, score, evidence);
          source = 'template';
        }

        const result = {
          url,
          verdict,
          score,
          evidence,
          plainExplanation: explanationObj.plainExplanation,
          advice: explanationObj.advice,
          cached: false,
          source,
          timestamp: new Date().toISOString()
        };

        analysisCache.set(url, result);
        return sendJson(res, 200, result);

      } catch (err) {
        return sendJson(res, 500, {
          error: err.message,
          verdict: 'Suspicious',
          score: 50,
          evidence: ['Local server error during check'],
          plainExplanation: 'Unable to complete deep evaluation due to a local server error.',
          advice: 'Exercise caution and verify the URL manually.',
          source: 'error-fallback'
        });
      }
    });
    return;
  }

  sendJson(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`[ScamLens Server] Running on http://localhost:${PORT}`);
  console.log(`[ScamLens Server] Gemini API configured: ${!!GEMINI_API_KEY}`);
});

export default server;
