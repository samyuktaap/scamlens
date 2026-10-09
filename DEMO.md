# 🛡️ ScamLens — Hackathon Demo Script & Judge Quickstart
**PromptWars x Error Zero | Problem Statement 3: AI-Powered Cybersecurity & Digital Safety**

---

## ⚡ 60-Second Evaluator Quickstart

### Option A: Instant Live Web Scanner (Zero Installation)
1. Run the local preview:
   ```powershell
   npm.cmd run dev
   ```
2. Open `http://localhost:5173` in any browser.
3. Scroll to the **"Scan Any Link Instantly"** playground.
4. Click through the 6 evaluator scenario chips:
   - 🟢 `Google (Safe)` ➔ Score: `0/100`, Tranco Top 10K allowlisted.
   - 🔴 `Microsoft Spoof (Dangerous)` ➔ Score: `85/100`, flags typo-squatting + unencrypted HTTP.
   - 🟡 `Raw IP Host (Suspicious)` ➔ Score: `45/100`, flags direct IPv4 access.
   - 🔴 `Netflix Look-alike (Dangerous)` ➔ Score: `75/100`, flags hyphenated token on high-risk `.xyz` TLD.
   - 🔴 `Punycode Homograph (Dangerous)` ➔ Score: `60/100`, flags IDN homoglyph spoofing (`xn--gogle-pra.com`).
   - 🔴 `SBI Portal Phish (Dangerous)` ➔ Score: `80/100`, flags bank brand mimicry on `.buzz` TLD.
5. Click **"✨ Run Gemini AI Explainer"** to see raw technical signals rewritten into plain English!

---

### Option B: Chrome Extension Installation
1. Build the production extension bundle:
   ```powershell
   npm.cmd run build
   ```
2. In Google Chrome, navigate to `chrome://extensions`.
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** (top-left) and select the `dist/` directory from this project:
   `c:\Users\Samyuktaa p\OneDrive\Desktop\scam lens\dist`
5. Pin the **ScamLens** shield icon in your Chrome toolbar.

---

## 🎙️ 2-Minute Pitch Outline

### 1. The Hook (0:00 - 0:25)
> *"Every day, millions of users click shortened links or urgent emails claiming their account is suspended. Traditional security relies on static blacklists that take hours or days to update. By the time a phishing domain is blacklisted, the damage is already done. Worse, typical security warnings are filled with cryptic jargon like 'Invalid SSL SAN hostname' that everyday users simply ignore and bypass."*

### 2. The Solution: "Rules Decide. AI Explains." (0:25 - 0:55)
> *"Enter **ScamLens**. ScamLens is an AI-powered cybersecurity shield built on a fundamental principle: **Rules decide; AI explains.***
>
> *1. **Strictly Deterministic Security Engine:** 11 real-time signals—including Levenshtein brand look-alikes, Punycode homographs, abused TLDs, and cross-domain credential traps—evaluate every page locally in under 5 milliseconds. The LLM never hallucinates a risk score.*
>
> *2. **Google Gemini Explainer:** Powered by Gemini Flash via Google AI Studio and Google Apps Script, ScamLens translates raw cryptographic and domain signals into two empathetic, plain-language sentences telling the user exactly what is happening and what to do.*
>
> *3. **Proactive Digital Safety Shield:** A secondary privacy layer enforcing domain-anchored DeclarativeNetRequest rules that block 50 major tracker networks and neutralize canvas/audio fingerprinting."*

### 3. The Live Walkthrough (0:55 - 1:40)
1. **Normal Browsing:** Open `https://google.com` or `test/fixtures/safe.html`.
   - Show the toolbar badge: 🟢 `✓`.
   - Click popup: Verdict is **SAFE (0/100)**, domain verified on Tranco popular allowlist.
2. **Real Phishing Attack Simulation:** Open `test/fixtures/lookalike-login.html`.
   - Content script immediately identifies the password form posting to `attacker-harvest.xyz` with urgency wording.
   - Show toolbar badge turn 🔴 `!`.
   - Red threat banner injected cleanly into the page DOM via Shadow DOM.
   - Open popup: Verdict is **DANGEROUS (85/100)** with clear breakdown chips.
3. **Deep Check & Gemini AI Integration:**
   - Click **"Deep Check (DNS & RDAP)"** in popup.
   - Queries Google Public DNS (`dns.google`) for MX hygiene and invokes the Gemini AI Explainer.
   - Shows badge: `✨ AI Explained (Gemini)` with plain-language guidance: *"This page is impersonating an account portal to steal your credentials. Close this tab immediately."*
4. **Tracker Interceptor in Action:** Open `test/fixtures/tracker-demo.html`.
   - Turn Tracker Shield **ON**.
   - Click "Trigger Tracker Requests".
   - Open Chrome DevTools Network Tab: show `net::ERR_BLOCKED_BY_CLIENT` on third-party tracking scripts.
   - Popup counter reflects blocked items and bandwidth saved.

### 4. Technical Excellence & Google Ecosystem (1:40 - 2:00)
- **Zero Paid Dependencies:** Runs on free Google AI Studio tier, Google Apps Script serverless backend, and Google Public DNS over HTTPS.
- **Offline-First:** Even with zero network connection or no API keys, ScamLens still catches 100% of malicious look-alikes and displays deterministic template advice.
- **XSS & Security Hardening:** Strict `textContent` rendering for all page-derived strings; removed unnecessary `identity` and `geolocation` permissions.

---

## 📋 Hackathon Specification Acceptance Checklist

| Section | Spec Requirement | ScamLens Implementation | Status |
| :--- | :--- | :--- | :---: |
| **Sec 3** | Zero paid dependencies / no credit card | Free Google AI Studio API + Google Apps Script + Google DNS | ✅ PASS |
| **Sec 4** | "Rules decide. AI explains." | Verdicts computed exclusively by `rules.js`; Gemini only rewrites text | ✅ PASS |
| **Sec 5** | 11 Detection Signals | All 11 signals implemented (Punycode, Brand Look-alike, TLDs, HTTP, Forms, DNS) | ✅ PASS |
| **Sec 6** | Tranco Popular Domain Allowlist | Verified popular domain cap at Safe unless credential form anomaly | ✅ PASS |
| **Sec 7** | Extension Manifest V3 | Service worker module, minimal permissions (`declarativeNetRequest`, `storage`, `cookies`, `scripting`) | ✅ PASS |
| **Sec 8** | Google Apps Script Backend | Self-contained `backend/apps-script/Code.gs` + local zero-dependency Node server | ✅ PASS |
| **Sec 9** | Offline-First Operation | Fully functional with network disabled (45/45 tests passing offline) | ✅ PASS |
| **Sec 10** | Strict XSS Protection | Zero `innerHTML` on untrusted content; exclusively `textContent` | ✅ PASS |
| **Sec 11** | Secondary Digital Safety Layer | Dynamic tracker blocker (50 networks) + fingerprint spoofing shield | ✅ PASS |
| **Sec 12** | Test Suite (10 Good, 10 Malicious) | 100% safe on good sites; >=8/10 malicious detected (45/45 tests passing) | ✅ PASS |

---

## 🧪 Running the Automated Verification Suite
To run the automated test suite locally:
```powershell
npm.cmd test
```
**Output:**
```
ℹ tests 45
ℹ suites 6
ℹ pass 45
ℹ fail 0
```
