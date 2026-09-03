# Pengu1n AI Dashboard

React + Tailwind frontend for the Pengu1n AI FastAPI scanner.

## Install

```bash
cd frontend
npm install
```

## Environment variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

| Variable | Required | Purpose |
|---|---|---|
| `VITE_API_BASE_URL` | No (defaults to `http://127.0.0.1:8000`) | FastAPI origin |
| `VITE_API_KEY` | No | Optional default `X-API-Key`. Prefer Settings in the UI for local development. |

`.env` is gitignored. Do not put real secrets in source or in `.env.example`.

You can also paste an API key on the Settings page. That value is stored only in browser `localStorage` and is sent as `X-API-Key`.

## Run the frontend

```bash
npm run dev
```

The Vite app listens on `http://localhost:5173`.

## Connect to FastAPI

1. Start the backend from `backend/` (virtualenv + `uvicorn app.main:app --reload`).
2. Ensure `PENGU1N_API_KEYS` is set in `backend/.env`.
3. Ensure CORS allows the dashboard origin (`PENGU1N_CORS_ORIGINS`, default `http://localhost:5173,http://127.0.0.1:5173`).
4. Open the dashboard, add the same API key in Settings (or `VITE_API_KEY`), then create a scan.

The UI talks to the existing API only:

- `POST /scan`
- `GET /scans`
- `GET /scans/{scan_id}`
- `GET /scan/{scan_id}/report`
- `GET /health` (public)

It does not invent scan results, findings, or CVEs.

## Example development workflow

```bash
# Terminal 1
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Terminal 2
cd frontend
npm run dev
```

Then open `http://localhost:5173`, set the API key, and run a scan against an authorized target such as `127.0.0.1`.

## Build

```bash
npm run build
```
