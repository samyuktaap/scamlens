# ScamLens — Google Apps Script Backend Setup

ScamLens utilizes a **Google Apps Script Web App** as a zero-cost, serverless backend. It provides an authentic Google ecosystem integration connecting Google AI Studio (Gemini 1.5/2.0 Flash) and Google Safe Browsing APIs.

## Key Architecture Principle: "Rules Decide. AI Explains."
- Threat verdicts (`Safe`, `Suspicious`, `Dangerous`) and numerical risk scores (`0-100`) are computed **strictly deterministically** by the rules engine.
- Gemini is **never** permitted to compute scores or alter verdicts. Its role is exclusively to translate raw technical signals into empathetic, plain-language guidance for non-technical users.

---

## 🚀 3-Minute Deployment Steps

### 1. Create Google Apps Script Project
1. Navigate to [script.google.com](https://script.google.com) and click **+ New Project**.
2. Rename the project to `ScamLens-Backend`.
3. In the left panel, replace the contents of `Code.gs` with [`backend/apps-script/Code.gs`](file:///c:/Users/Samyuktaa%20p/OneDrive/Desktop/scam%20lens/backend/apps-script/Code.gs).
4. Click **Project Settings** (gear icon ⚙️) and check the box **"Show 'appsscript.json' manifest file in editor"**.
5. Switch back to the Editor tab, select `appsscript.json`, and replace with [`backend/apps-script/appsscript.json`](file:///c:/Users/Samyuktaa%20p/OneDrive/Desktop/scam%20lens/backend/apps-script/appsscript.json).

### 2. Configure Environment Variables (Script Properties)
In **Project Settings** (⚙️) ➡️ scroll down to **Script Properties** ➡️ click **Edit script properties**:
| Property | Value | Description |
| :--- | :--- | :--- |
| `GEMINI_API_KEY` | *(Your Google AI Studio API Key)* | Free tier from [aistudio.google.com](https://aistudio.google.com) |
| `SAFE_BROWSING_API_KEY` | *(Optional)* | Google Cloud Safe Browsing API v4 key |
| `SHARED_TOKEN` | `scamlens-demo-token` | Protects the endpoint from unauthorized callers |

*Note: If no API keys are provided, ScamLens gracefully falls back to deterministic template advice.*

### 3. Deploy as Web App
1. Click the blue **Deploy** button in the top right ➡️ **New deployment**.
2. Select type: **Web app** (gear icon ⚙️ ➡️ Web app).
3. Fill in configuration:
   - **Description**: `ScamLens Production v1`
   - **Execute as**: `Me (<your-email>)`
   - **Who has access**: `Anyone` (required for extension & web app calls)
4. Click **Deploy**.
5. Copy the generated **Web app URL** (e.g. `https://script.google.com/macros/s/AKfycb.../exec`).

### 4. Link with Extension
Open the ScamLens extension settings or popup and paste the Web App URL. All "Run Deep Check" actions will now query this endpoint!

---

## 📡 API Contract

### Health Check: `GET /exec`
```json
{
  "status": "ok",
  "service": "ScamLens Backend",
  "version": "1.0.0",
  "timestamp": "2026-10-09T06:20:00.000Z",
  "geminiConfigured": true,
  "safeBrowsingConfigured": false
}
```

### Deep Analysis: `POST /exec`
**Request Payload:**
```json
{
  "token": "scamlens-demo-token",
  "url": "https://secure-login.micros0ft-account.xyz/auth",
  "verdict": "Dangerous",
  "score": 85,
  "evidence": [
    "Domain impersonates known brand \"Microsoft\"",
    "High-risk top level domain (.xyz)",
    "Password/credential form targets external domain"
  ],
  "model": "gemini-1.5-flash",
  "forceRefresh": false
}
```

**Response Payload:**
```json
{
  "url": "https://secure-login.micros0ft-account.xyz/auth",
  "verdict": "Dangerous",
  "score": 85,
  "evidence": [
    "Domain impersonates known brand \"Microsoft\"",
    "High-risk top level domain (.xyz)",
    "Password/credential form targets external domain"
  ],
  "plainExplanation": "This website is a fake login page attempting to impersonate Microsoft to steal your password.",
  "advice": "Do not enter passwords or personal info. Close this tab immediately.",
  "cached": false,
  "source": "gemini",
  "timestamp": "2026-10-09T06:20:01.250Z"
}
```
