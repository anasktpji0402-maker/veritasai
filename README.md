# Veritas AI v2 — Live Integration

## Included
- Real Gemini AI analysis through a server-side proxy
- Google Safe Browsing live URL threat intelligence
- Google Fact Check Tools live claim-search
- LocalStorage scan history
- Web Share API for mobile sharing
- No provider secret is placed in the browser

## Setup
1. Install Node.js 18+.
2. Copy `.env.example` to `.env`.
3. Add API keys.
4. Run:
   npm install
   npm start
5. Open http://localhost:3000

## API keys
Create/configure the required Google API credentials in the relevant Google developer consoles. Enable the APIs for the project and restrict the keys appropriately.

IMPORTANT: Do not publish `.env`, and do not hard-code keys into the frontend.

## Production
Deploy the Node server (or equivalent backend/serverless functions) and set environment variables in the hosting provider. The browser calls `/api/analyze`; the backend calls Gemini, Safe Browsing and Fact Check Tools.

## Notes
Fact-check search returns published ClaimReview data; it is not a universal truth oracle. Safe Browsing identifies resources matching Google's supported threat lists. AI output is probabilistic and should be treated as decision support, not proof.
