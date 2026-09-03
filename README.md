# Pengu1n AI

**AI-assisted security assessment platform for authorized scanning, security research, and controlled bug-bounty workflows.**

Pengu1n AI combines network discovery, service detection, HTTP/TLS security analysis, vulnerability intelligence, risk assessment, persistent scan history, structured security reporting, and a React-based security dashboard — built around an **evidence-first workflow**.

> ⚠️ **Authorization Required**
> Pengu1n AI must only be used against systems you own or for which you have explicit, documented permission to perform security testing.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
  - [Requirements](#requirements)
  - [Backend Setup](#backend-setup)
  - [Frontend Setup](#frontend-setup)
- [Scan Profiles](#scan-profiles)
- [Responsible Use](#responsible-use)
- [Technology Stack](#technology-stack)
- [Contributing](#contributing)

---

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | Network Discovery | Custom Python TCP scanner — no Nmap dependency |
| 2 | Service Detection | Banner and version identification |
| 3 | HTTP Security Analysis | Non-destructive header/config checks |
| 4 | TLS Security Analysis | Handshake, version, and certificate inspection |
| 5 | Risk Engine | Five-tier severity classification |
| 6 | Vulnerability Intelligence | OSV-based CVE correlation with version verification |
| 7 | Scope Enforcement | Allow/exclude lists for bug-bounty scans |
| 8 | Rate Limiting | Enforced outbound network throttling |
| 9 | Persistent Scan History | SQLite-backed storage |
| 10 | Security Reports | Structured, evidence-based reporting |
| 11 | API-Key Authentication | Header-based access control |
| 12 | React/Tailwind Dashboard | Security operations console UI |
| 13 | Optional AI Reporting | Disabled by default; pluggable provider architecture |

### Network Discovery
- Configurable scan profiles (common-port and extended-port scanning)
- Open-port and service identification
- Banner and version detection
- Connection timeouts and rate-limited requests

### HTTP Security Scanner
Non-destructive checks against HTTP/HTTPS services, including:
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- HSTS
- Server header disclosure
- HTTP → HTTPS redirect behavior
- Cookie security attributes
- Safe HTTP method / TRACE observation

### TLS Security Scanner
Inspects TLS configuration without attempting exploitation:
- TLS handshake and version detection
- Certificate availability, validity, and expiration
- Certificate hostname matching
- Legacy vs. modern TLS version flagging

### Vulnerability Intelligence
- Uses [OSV](https://osv.dev/) as the external intelligence source
- Affected-version verification before a finding is created
- Confidence levels, CVE references, and duplicate prevention
- Does **not** assume a matching product name means a system is vulnerable

### Risk Engine
Findings are classified as `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. Overall scan severity reflects the highest-severity finding.

### Scope Enforcement & Rate Limiting
```
API Authentication → Target Validation → Scope Validation → Rate Limiting → Network Scanner
```
- Allowed/excluded hosts
- Requests-per-second limits
- Profile-specific restrictions
- Out-of-scope targets are rejected outright

### Security Reports
Each report includes: metadata, target, scan profile, duration, overall risk, severity counts, affected services, prioritized findings, executive summary, evidence, recommendations, and CVE summary.

### AI-Assisted Reporting
AI enhancement is **disabled by default** and not required to generate reports:
```
Scanner → Structured Findings → Deterministic Report → Optional AI Enhancement
```

### Dashboard
A React + Tailwind security operations console (not a generic CRUD dashboard) with:
- Dashboard overview (total scans, posture, severity distribution, recent targets)
- New Scan workflow (target + profile → run scan)
- Scan History (searchable)
- Scan Details (ports, services, findings, evidence, recommendations)
- Security Report view (executive summary → risk overview → findings → evidence → recommendations → CVE intel)
- Settings (API base URL, API key, connection status — key stored locally, never hardcoded)

---

## Architecture

```
                         ┌─────────────────────┐
                         │   React Dashboard   │
                         │  React + Tailwind   │
                         └──────────┬──────────┘
                                    │ REST API (X-API-Key)
                                    ▼
                         ┌─────────────────────┐
                         │       FastAPI       │
                         │      API Layer      │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │    Scan Manager     │
                         └──────────┬──────────┘
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
       Port Scanner          Service Detector       HTTP Scanner
              └─────────────────────┼─────────────────────┘
                                    ▼
                             TLS Scanner
                                    ▼
                             Risk Engine
                                    ▼
                           Vulnerability Intel
                                    ▼
                           Report Generator
                          ┌─────────┴─────────┐
                          ▼                   ▼
                  Deterministic Report   AI Enhancer
                          └─────────┬─────────┘
                                    ▼
                            SQLite Database
```

**Pipeline:**
```
Discovery → Service Identification → Security Analysis → Vulnerability Intelligence → Risk Assessment → Report
```

---

## Installation

### Requirements

| Tool | Version |
|------|---------|
| Python | 3.10+ |
| Node.js | 18+ |
| npm | latest |
| Git | any recent |

### Clone the Repository

```bash
git clone https://github.com/hillaryns/pengu1n-ai.git
cd pengu1n-ai
```

### Backend Setup

```bash
cd backend
```

**Create and activate a virtual environment (Windows):**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

**Install dependencies:**
```powershell
pip install -r requirements.txt
```

**Configure environment variables** — create `backend/.env`:
```env
PENGU1N_API_KEYS=change-this-development-key

DATABASE_URL=sqlite:///./pengu1n.db

PENGU1N_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

PENGU1N_AI_REPORT_ENABLED=false

PENGU1N_AI_PROVIDER=none

# Optional future AI provider key
# PENGU1N_AI_API_KEY=
```

> ⚠️ Never commit your real `.env` file.

**Start the backend** (from `backend/`):
```powershell
python -m uvicorn app.main:app --reload
```

| Endpoint | URL |
|----------|-----|
| API | http://127.0.0.1:8000 |
| Docs | http://127.0.0.1:8000/docs |
| Health check | http://127.0.0.1:8000/health |

Keep this terminal running.

### Frontend Setup

Open a second terminal from the project root:

```powershell
cd frontend
npm install
```

**Create `frontend/.env`:**
```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

> The API key itself is entered through the dashboard's Settings page — not stored in `.env`.

**Start the dashboard:**
```powershell
npm run dev
```

Vite will serve the dashboard at a local URL similar to `http://localhost:5173`.

---

## Scan Profiles

| Profile | Purpose |
|---------|---------|
| `quick` | Fast scan of a small set of commonly exposed ports |
| `standard` | Balanced security assessment |
| `deep` | Extended port and service coverage |
| `bug_bounty` | Scope-controlled scanning with conservative request limits |

---

## Responsible Use

Pengu1n AI is intended for:
- Authorized penetration testing
- Security research
- Local security labs
- Bug-bounty programs where the target and testing method are explicitly permitted
- Systems owned by the operator
- Controlled educational environments

**Do not use Pengu1n AI to:**
- Scan systems without permission
- Bypass authorization
- Steal credentials
- Brute-force accounts
- Exploit systems
- Deploy malware
- Perform denial-of-service attacks
- Modify systems without authorization

Always verify the target's scope and testing policy before performing an assessment.

---

## Technology Stack

**Backend**
- Python, FastAPI, Pydantic, SQLAlchemy, SQLite, HTTPX, Uvicorn, python-dotenv

**Frontend**
- React, TypeScript, Vite, Tailwind CSS, React Router

**Security Components**
- Python `socket` / `ssl`
- OSV vulnerability intelligence
- Custom scope manager
- Custom rate limiter
- Custom risk engine
- Structured security findings schema

---

## Contributing

Contributions are welcome. Before submitting a change:

- Keep scanner behavior modular.
- Avoid hardcoded secrets.
- Add tests for new functionality.
- Preserve existing API behavior where possible.
- Do not add exploit functionality without a clear security and authorization model.
- Run the backend test suite.
- Run the frontend build.

---

## Status

Pengu1n AI is currently under **active development**.
