# Scam URL/Message Checker

A phishing/scam detector for WhatsApp and SMS messages common in India. Paste a link or a message and get a Safe / Suspicious / Dangerous verdict with a one-line reason.

- `frontend/` — Next.js UI (built by a collaborator)
- `backend/` — Python + FastAPI detection engine (this is the part described below)

## What the backend checks

1. **URL Safety Check** — Google Safe Browsing API (malware/phishing feeds)
2. **Domain Age Check** — WHOIS lookup, flags domains registered under 30 days ago
3. **Brand Impersonation Check** — Levenshtein distance against ~20 commonly-impersonated Indian brands (SBI, Paytm, PhonePe, Amazon, LIC, etc.)
4. **Scam Message Text Check** — keyword/regex scoring for phishing language (KYC threats, OTP requests, lottery scams, urgency tactics)
5. **Verdict Engine** — combines all signals into Safe / Suspicious / Dangerous + a plain-English reason

## Running it locally

You need two terminals — one for the backend, one for the frontend.

### Backend (FastAPI)

```bash
cd backend
python -m venv venv
./venv/Scripts/activate   # on macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env       # optionally paste a Google Safe Browsing API key in here
uvicorn app.main:app --reload --port 8000
```

Runs at `http://localhost:8000`. Without a Safe Browsing API key, that one check is skipped gracefully — everything else still works.

### Frontend (Next.js)

```bash
cd frontend
npm install
cp .env.local.example .env.local   # points the UI at the backend
npm run dev
```

Open `http://localhost:3000`.

## WhatsApp Integration

Users can forward suspicious messages directly to a WhatsApp number and get a verdict + report link back automatically, powered by Twilio's WhatsApp Sandbox.

**Setup:**
1. Sign up for Twilio and activate the WhatsApp Sandbox (**Console → Messaging → Try it out → WhatsApp**).
2. Join the sandbox from your phone using the provided code.
3. Expose your local backend publicly (for testing) using ngrok:
   ```bash
   ngrok http 8000
   ```
4. In Twilio Sandbox Settings, set **"When a message comes in"** to:
   `https://<your-ngrok-url>/whatsapp-webhook` (Method: `POST`).

*Note: Free ngrok URLs change every restart — update the Twilio webhook and `.env` values each time you restart ngrok.*

## Result Reports

Each scan is saved with a short ID and viewable at `/result/{id}` on the frontend. Currently stored in-memory (`store.py`) — results are lost on backend restart. Swap for a real DB (SQLite/Postgres/Redis) for persistence.

## Environment Variables

### Backend (`backend/.env`)
```env
GOOGLE_SAFE_BROWSING_API_KEY= # optional
CORS_ORIGINS=http://localhost:3000,https://<your-vercel-url>
WEBSITE_URL=https://<your-frontend-url>
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
```

### Frontend (`frontend/.env.local`)
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## Deployment

- **Frontend** — deployed on Vercel, set `NEXT_PUBLIC_API_URL` in project Environment Variables to the public backend URL.
- **Backend** — currently run locally + exposed via ngrok during testing. For a permanent setup, deploy to Railway/Fly.io (persistent server needed — avoid serverless platforms since result storage is in-memory).

**Important:** If using ngrok, all fetch calls from the frontend must include the header `"ngrok-skip-browser-warning": "true"` to bypass ngrok's free-tier interstitial page.
