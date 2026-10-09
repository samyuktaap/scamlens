# ScamLens

> **Rules decide. AI explains.**  
> Built for PromptWars x Error Zero | Problem Statement 3: AI-Powered Cybersecurity & Digital Safety.

ScamLens is an intelligent browser extension (with offline-first rule verification and AI explanations) that inspects websites and links in real-time, displays an immediate Safe / Suspicious / Dangerous verdict backed by clear evidence, and explains what actions to take in plain language.

---

## Core Principles

- **Rules Decide, AI Explains**: Security verdicts and risk scores are calculated 100% deterministically by local heuristic rules and lookups. The LLM never invents scores or verdicts—it provides friendly, plain-language explanations and recommended actions.
- **Offline-First**: All baseline rules run entirely within the browser without requiring network access or external APIs. Online lookups only enrich the analysis.
- **Privacy by Design**: Only domain hostnames are sent for remote backend lookups. Full URLs are only inspected if explicitly opted into. No user data or credentials leave the device.
- **No Paid Dependencies**: Strictly uses free and developer tiers (Google AI Studio, Google Apps Script, Google Public DNS).

---

## Permissions Justification

| Permission | Justification |
| :--- | :--- |
| `declarativeNetRequest` | Enforces high-performance, domain-anchored blocking of invasive tracker networks. |
| `declarativeNetRequestFeedback` | Verifies blocked rule counts in developer and diagnostic views. |
| `webRequest` | Observer used to monitor and tally third-party tracker requests when shield is active. |
| `cookies` | Analyzes tracking cookie volume and facilitates privacy cleaning. |
| `storage` | Stores site safety verdicts, shield state, and logs locally on device (`chrome.storage.local`). |
| `tabs` / `activeTab` | Retrieves the active page URL and coordinates tab analysis on navigation. |
| `scripting` | Executes local storage cleanup when user detonate privacy cleanup actions. |

---

## Google Services Used

- **Google Antigravity**: Primary IDE and agentic development environment.
- **Gemini API via Google AI Studio**: Generates empathetic, plain-language security explanations from deterministic rule outputs.
- **Google Apps Script**: Free, zero-maintenance serverless backend endpoint running lookups and caching.
- **Google Public DNS over HTTPS**: Lookups for MX/TXT DNS records on look-alike domains without third-party services.

---

## Getting Started

### Development & Quick Commands
```bash
# Run 45 unit and integration tests
npm test

# Build extension into dist/
npm run build

# Start live web scanner & landing page preview (http://localhost:5173)
npm run dev

# Start zero-dependency local fallback server (http://localhost:3000)
npm run server
```

### Loading the Extension in Chrome
1. Navigate to `chrome://extensions/` in Chrome.
2. Enable **Developer mode** in the top-right corner.
3. Click **Load unpacked** and select the `dist/` directory generated after running `npm run build`.

---

## 📚 Project Documentation & Quick Links
- **[DEMO.md](file:///c:/Users/Samyuktaa%20p/OneDrive/Desktop/scam%20lens/DEMO.md)**: 2-minute pitch outline, judge walkthrough, and live scenario checklist.
- **[Google Apps Script Backend Guide](file:///c:/Users/Samyuktaa%20p/OneDrive/Desktop/scam%20lens/backend/apps-script/README.md)**: Step-by-step 3-minute deployment guide for the free Google Apps Script web app.
- **[Local Test Fixtures](file:///c:/Users/Samyuktaa%20p/OneDrive/Desktop/scam%20lens/test/fixtures/)**: Safe benchmarks, phishing simulation with cross-domain forms, and tracker blocking tests.

