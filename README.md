# Pengu1n AI

### Security Assessment Platform for Authorized Scanning

Pengu1n AI is an AI-assisted cybersecurity assessment platform designed for authorized security testing, security research, and controlled bug-bounty workflows.

It combines network discovery, service detection, HTTP/TLS security analysis, vulnerability intelligence, risk assessment, persistent scan history, structured security reports, and a React-based security dashboard.

The project is designed around an evidence-first workflow:

Authorization Required

Pengu1n AI must only be used against systems you own or systems for which you have explicit permission to perform security testing.


__INSTALLATION___
Requirements
Recommended environment:
Python 3.10+
Node.js 18+
npm
Git

## Clone the Repository

```bash
git clone https://github.com/hillaryns/pengu1n-ai.git
cd pengu1n-ai
```
Backend Installation
Enter the backend directory:
```bash
cd backend
```
Windows
```powershell
python -m venv .venv
```
Activate it
```powershell
.venv\Scripts\activate
```
Install Dependencies 
```powershell
pip install -r requirements.txt
```
Backend Configuration
Create: 
```
backend/.env
```
example:
```env
PENGU1N_API_KEYS=change-this-development-key

DATABASE_URL=sqlite:///./pengu1n.db

PENGU1N_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

PENGU1N_AI_REPORT_ENABLED=false

PENGU1N_AI_PROVIDER=none

# Optional future AI provider key
# PENGU1N_AI_API_KEY=
```
Never commit the real .env file

Start the Backend
from:
```
backend/
```
Run
```powershell
python -m uvicorn app.main:app --reload
```
The backend will be available at:
```
http://127.0.0.1:8000
```
API Documentation:
```
http://127.0.0.1:8000/docs
```
Health check:
```
http://127.0.0.1:8000/health
```
Keep this terminal running.

FRONTEND INSTALLATION
open a second terminal.
from the project root:
```powershell
cd frontend
```
Install dependencies:
```powershell
npm install
```
create:
```
frontend.env
```
example:
```
VITE_API_BASE_URL=http://127.0.0.1:8000
```
The API key can be entered through the settings page.

START THE DASHBOARD
Run:
```powershell
npm run dev
```
Vite will provide a local URL similar to :
```
http://localhost:5173
```
open that address in your browser


!!!Responsible Use!!!

Pengu1n AI is intended for:

Authorized penetration testing
Security research
Local security labs
Bug-bounty programs where the target and testing method are explicitly permitted
Systems owned by the operator
Controlled educational environments

Do not use Pengu1n AI to:

scan systems without permission
bypass authorization
steal credentials
brute-force accounts
exploit systems
deploy malware
perform denial-of-service attacks
modify systems without authorization

Always verify the target's scope and testing policy before performing an assessment.






Pengu1n AI is currently under active development.

Current functionality includes:

1. Custom TCP port scanning
2. Service detection
3. Banner/version detection
4. HTTP security analysis
5. TLS security analysis
6. Risk classification
7. Scan profiles
8. Scope enforcement
9. Rate limiting
10. Vulnerability intelligence
11. CVE correlation
12. SQLite persistence
13. Security report generation
14. API-key authentication
15. React/Tailwind dashboard
16. Optional AI report architecture

FEATURES INCLUDES
1. Network Discovery
Pengu1n AI uses a custom Python TCP scanner to identify exposed services.

Features include:

TCP port scanning
Configurable scan profiles
Common-port scanning
Extended-port scanning
Open-port identification
Service identification
Banner detection
Version detection
Connection timeouts
Rate-limited network requests

The scanner does not require Nmap.

2. Scan Profiles
   | Profile      | Purpose                                                    |
| ------------ | ---------------------------------------------------------- |
| `quick`      | Fast scan of a small set of commonly exposed ports         |
| `standard`   | Balanced security assessment                               |
| `deep`       | Extended port and service coverage                         |
| `bug_bounty` | Scope-controlled scanning with conservative request limits |

3. HTTP security scanner
   The HTTP scanner performs non-destructive security checks against HTTP/HTTPS services.

Current checks include:

Content-Security-Policy
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
HSTS
Server header disclosure
HTTP-to-HTTPS redirect behavior
Cookie security attributes
Safe HTTP method/TRACE observation

4. TLS Security Scanner
   Pengu1n AI can inspect TLS services without attempting exploitation.

Current checks include:

TLS handshake
TLS version
Certificate availability
Certificate validity
Certificate expiration
Certificate hostname matching
Legacy TLS versions
Modern TLS versions

5. Vulnerability Intelligence
   Detected software and versions can be correlated against vulnerability intelligence.

The current implementation uses OSV as an external vulnerability intelligence source.

The system supports:

CVE identification
Affected-version verification
Confidence levels
CVE references
Service/version correlation
Duplicate prevention
Graceful handling of unavailable intelligence
Pengu1n AI does not automatically assume that a matching product name means a system is vulnerable.

Version verification is performed before creating a vulnerability finding where sufficient version information is available.

6. Risk Engine
   Findings are classified using five severity levels
   CRITICAL
   HIGH  
   MEDIUM
   LOW
   INFO
   The overall scan severity is determined from the highest-severity finding.

8. Scope Enforcement
   Bug-bounty scans require explicit target scope.
   Scope controls include:

Allowed hosts
Excluded hosts
Requests-per-second limits
Target validation
Profile-specific restrictions

The scanner rejects targets that do not satisfy the configured scope.

9. Rate Limiting

Pengu1n AI includes an enforced outbound network rate limiter.

Rate limiting is applied to network operations such as:

TCP connections
Service probes
HTTP requests
TLS connections
Vulnerability intelligence requests

The rate limiter is separate from API authentication.
API Authentication
        ↓
Target Validation
        ↓
Scope Validation
        ↓
Rate Limiting
        ↓
Network Scanner

10. Security Reports

Completed scans can be converted into structured security reports.

Reports include:

Report metadata
Target
Scan profile
Scan duration
Overall risk
Severity counts
Affected services
Prioritized findings
Executive summary
Evidence
Recommendations
CVE summary
AI-enhancement status

11. AI-Assisted Reporting

Pengu1n AI includes an AI report enhancement architecture.

AI enhancement is disabled by default.

The scanner does not require an AI provider to generate reports.

The architecture separates:
Scanner
   ↓
Structured Findings
   ↓
Deterministic Report
   ↓
Optional AI Enhancement

12. Dashboard

Pengu1n AI includes a React and Tailwind CSS dashboard.

The interface is designed around a security operations console rather than a generic CRUD dashboard.

Dashboard

The main dashboard provides:

Total scans
Recent scans
Overall security posture
Severity distribution
Latest findings
Recent targets
Quick scan access

Design direction:

┌───────────────────────────────────────────────────────┐
│ Pengu1n AI                              Start Scan     │
├───────────────┬───────────────────────────────────────┤
│               │                                       │
│ Dashboard     │ Security Overview                    │
│               │                                       │
│ New Scan      │ ┌────────┐ ┌────────┐ ┌────────┐    │
│               │ │ Scans  │ │ Medium │ │  High  │    │
│ History       │ └────────┘ └────────┘ └────────┘    │
│               │                                       │
│ Settings      │ Severity Distribution                │
│               │                                       │
│               │ Recent Assessments                   │
│               │                                       │
└───────────────┴───────────────────────────────────────┘

13. New Scan UI

The New Scan page provides a simple assessment workflow

Target
┌─────────────────────────────────────────────┐
│ example.com                                 │
└─────────────────────────────────────────────┘

Profile
┌─────────────────────────────────────────────┐
│ Standard                                  ▼ │
└─────────────────────────────────────────────┘

                 [ Run Scan ]

14.Scan History UI

The scan history interface provides a searchable overview of previous assessments.Scan History UI

The scan history interface provides a searchable overview of previous assessments.

15. Scan Details UI

Each scan has a dedicated details page.

The page displays:

Target
Profile
Status
Duration
Start time
Completion time
Open ports
Detected services
Severity distribution
Findings
Evidence
Recommendations

16. Security Report UI

Reports are presented as readable security assessments rather than raw JSON.

The report interface contains:

Executive Summary
        ↓
Risk Overview
        ↓
Affected Services
        ↓
Prioritized Findings
        ↓
Evidence
        ↓
Recommendations
        ↓
CVE Intelligence

Each finding displays:

Severity
Finding ID
Category
Title
Description
Target
Port
Evidence
Recommendation
CVE ID when available
Confidence when available
References when available

17. Settings UI

The Settings page manages local dashboard configuration.

Available configuration includes:

API base URL
API key
Connection status

The API key is stored locally for development use and is not hardcoded into the frontend source.

Technology Stack
Backend
Python
FastAPI
Pydantic
SQLAlchemy
SQLite
HTTPX
Uvicorn
python-dotenv
Frontend
React
TypeScript
Vite
Tailwind CSS
React Router
Security Components
Python socket
Python ssl
OSV vulnerability intelligence
Custom scope manager
Custom rate limiter
Custom risk engine
Structured security findings

____ARCHITECHTURE___
                         ┌─────────────────────┐
                         │   React Dashboard   │
                         │ React + Tailwind    │
                         └──────────┬──────────┘
                                    │
                                    │ REST API
                                    │ X-API-Key
                                    ▼
                         ┌─────────────────────┐
                         │      FastAPI        │
                         │      API Layer      │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    Scan Manager     │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
       Port Scanner          Service Detector       HTTP Scanner
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    │
                                    ▼
                             TLS Scanner
                                    │
                                    ▼
                             Risk Engine
                                    │
                                    ▼
                         Vulnerability Intel
                                    │
                                    ▼
                           Report Generator
                                    │
                          ┌─────────┴─────────┐
                          │                   │
                          ▼                   ▼
                  Deterministic Report   AI Enhancer
                          │                   │
                          └─────────┬─────────┘
                                    ▼
                            SQLite Database

                            
```text
Discovery
    ↓
Service Identification
    ↓
Security Analysis
    ↓
Vulnerability Intelligence
    ↓
Risk Assessment
    ↓
```
Contributing

Contributions are welcome.

Before submitting a change:

Keep scanner behavior modular.
Avoid hardcoded secrets.
Add tests for new functionality.
Preserve existing API behavior where possible.
Do not add exploit functionality without a clear security and authorization model.
Run the backend test suite.
Run the frontend buil
Security Report

