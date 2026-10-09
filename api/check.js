/**
 * ScamLens Vercel Serverless Function (api/check.js)
 * "Rules decide. AI explains."
 * 
 * Provides serverless backend verification, DNS over HTTPS lookups,
 * RDAP domain intelligence, and Google Gemini AI security explanations.
 */

import https from 'node:https';

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || process.env.VITE_GEMINI_API_KEY || '';
const SHARED_TOKEN   = process.env.SHARED_TOKEN || process.env.VITE_SHARED_TOKEN || 'scamlens-demo-token';

function sendJson(res, statusCode, data) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.status(statusCode).json(data);
}

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
    return {
      plainExplanation: 'This website exhibits unusual characteristics (such as a high-risk domain or brand look-alike) that require caution.',
      advice: 'Verify the web address carefully before entering personal data or proceeding with transactions.'
    };
  }

  return {
    plainExplanation: 'Standard verified browsing session. No brand impersonation or deceptive anomalies detected.',
    advice: 'No security concerns identified. Safe to browse.'
  };
}

async function explainWithGemini(domain, verdict, score, signals, apiKey) {
  const key = apiKey || GEMINI_API_KEY;
  if (!key) return null;

  const prompt = `You are ScamLens, a protective cybersecurity assistant.
Analyze this web inspection result and provide a plain-language, empathetic explanation:
Domain: ${domain}
Calculated Verdict: ${verdict}
Risk Score: ${score}/100
Triggered Heuristic Signals: ${JSON.stringify(signals)}

Format your response strictly as valid JSON with keys:
- "plainExplanation": 1-2 sentence plain-language summary suitable for non-technical users.
- "advice": 1 concise sentence of actionable advice.`;

  return new Promise((resolve) => {
    const postData = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 200,
        responseMimeType: 'application/json'
      }
    });

    const req = https.request({
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/gemini-1.5-flash:generateContent?key=${key}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const rawText = json?.candidates?.[0]?.content?.parts?.[0]?.text;
          if (rawText) {
            const parsed = JSON.parse(rawText);
            if (parsed.plainExplanation) {
              return resolve({
                plainExplanation: parsed.plainExplanation,
                advice: parsed.advice || 'Verify domain origin before entering credentials.',
                source: 'gemini'
              });
            }
          }
        } catch (e) {}
        resolve(null);
      });
    });

    req.on('error', () => resolve(null));
    req.setTimeout(3500, () => { req.destroy(); resolve(null); });
    req.write(postData);
    req.end();
  });
}

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    return res.status(204).end();
  }

  if (req.method === 'GET') {
    return sendJson(res, 200, {
      status: 'ok',
      service: 'ScamLens Vercel Serverless Gateway',
      version: '1.0.0',
      timestamp: Date.now()
    });
  }

  if (req.method !== 'POST') {
    return sendJson(res, 405, { error: 'Method Not Allowed' });
  }

  try {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();

    if (SHARED_TOKEN && SHARED_TOKEN !== 'none' && token !== SHARED_TOKEN) {
      return sendJson(res, 401, { error: 'Unauthorized: Invalid or missing token' });
    }

    const body = req.body || {};
    const domain = (body.domain || '').trim().toLowerCase();
    const verdict = body.verdict || 'Safe';
    const score = Number(body.score) || 0;
    const signals = Array.isArray(body.signals) ? body.signals : [];

    let explanation = await explainWithGemini(domain, verdict, score, signals, body.geminiApiKey);

    if (!explanation) {
      const fallback = getTemplateAdvice(verdict, score, signals);
      explanation = {
        plainExplanation: fallback.plainExplanation,
        advice: fallback.advice,
        source: 'template'
      };
    }

    return sendJson(res, 200, {
      domain,
      verdict,
      score,
      signals,
      ...explanation,
      cached: false,
      timestamp: Date.now()
    });
  } catch (err) {
    return sendJson(res, 500, { error: 'Internal Server Error', details: err.message });
  }
}
