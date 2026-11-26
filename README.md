# UPI Shield AI – deployable package

```
site/      website (one index.html)  -> deploy on Vercel
backend/   FastAPI + Tesseract OCR   -> deploy on Render (Docker)
render.yaml  optional one-click Render setup
```

## 1. Deploy the backend (Render)
1. Push this whole folder to a GitHub repo.
2. Render -> New -> Web Service -> pick the repo.
   - Language: **Docker**   - Root Directory: **backend**   - Plan: Free
   (Or use New -> Blueprint, which reads `render.yaml`.)
3. Deploy. Open your Render URL: you should see `{"status":"ok", ...}`.
4. Copy the URL (e.g. https://upi-shield-backend-xxxx.onrender.com).

## 2. Point the site at the backend
Open `site/index.html`, find `const API_BASE = "..."` near the bottom and set it
to your Render URL (no trailing slash). Commit and push.

## 3. Deploy the site (Vercel)
Vercel -> Add New -> Project -> pick the repo -> set **Root Directory = site**
-> Framework: Other -> Deploy.

## 4. Allow the site in the backend (CORS)
Any Vercel address starting with `upi-shield` already works. For any other
address, in Render -> Environment set `ALLOWED_ORIGINS` to the site URL
(comma-separate several), then let it redeploy.

## Run locally
Backend: `cd backend && pip install -r requirements.txt && uvicorn main:app --port 8000`
(screenshots also need Tesseract installed: https://github.com/UB-Mannheim/tesseract/wiki).
Site: set `API_BASE` to `http://localhost:8000` and open `site/index.html`
via a local server, e.g. `cd site && python -m http.server 8080` -> http://localhost:8080.

Note: the free Render plan sleeps when idle; the first check can take ~1 minute.
