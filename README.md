# Honeytoken-Based Insider Threat Detector

A deception-based insider threat detection system built to identify and triage unauthorized access by internal actors using multi-format honeytokens (API keys, canary documents, database records) and dynamic risk-level alert triage.

**Academic Session:** 2026–27  
**Degree Track:** Bachelor of Technology in Computer Science and Engineering  
**Institution:** School of Computer Science and Engineering, IILM University, Greater Noida  
**Supervisor:** Mr. Atul Kumar Singh  

### Team Members
- **Aryan Singh (2410031399)** — Backend Lead & Architecture
- **Aniket Tiwari (2410031403)** — Listener Engine & Automated Testing
- **Sana Khan (2410031378)** — Validation Schemas & API Documentation
- **Saumya Kashyap (2410031737)** — Decoy Artifact Templates & Team Onboarding

---

## System Architecture Pipeline

```
[ Decoy Generators ] ──> Planted into Workspaces / Repos / Databases
        │
        ▼ (Triggered on Access)
[ Beacon / Listener Service ] (rate-limited, unauthenticated by design)
        │
        Extracts IP, Headers, Timestamp
        │
        ▼
[ Risk-Scoring Engine ]
        Computes Score: Asset Weight × Context × Frequency
        │
        ▼
[ WebSocket / SSE Dispatch ]
        │
        ▼
[ Security Admin Dashboard (UI) ] (auth-gated)
```

---

## Core Features

- **Multi-Format Decoys:** Support for canary documents (embedded web bugs/pixels), synthetic API keys, and database honeytoken entries.
- **Silent Telemetry Receiver:** Transparent 1x1 GIF listener capturing client IP (handling `X-Forwarded-For`), HTTP headers, and user-agents without raising suspicion.
- **Dynamic Risk-Level Alert Labeling:** Automated triage categorizing threats into **Low**, **Medium**, **High**, and **Critical** based on asset criticality, access context (e.g. outside business hours), and burst frequency.
- **Standardized API Contracts:** Structured response envelope `{status, data, error}` for consistent integration across services.

---

## Getting Started

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Git

### 2. Environment Setup
Clone the repository and set up a virtual environment:
```powershell
git clone https://github.com/Aryanite/Honeytoken-Based-Insider-Threat-Detector.git
cd Honeytoken-Based-Insider-Threat-Detector

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` if not already present:
```powershell
cp .env.example .env
```

### 4. Seed Test Data
Populate the database with sample honeytokens:
```powershell
python seed_test_data.py
```

### 5. Run the Application
Start the FastAPI server:
```powershell
python -m uvicorn backend.main:app --reload --port 8000
```
- Interactive Swagger API Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Alternative ReDoc: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- Health Check: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## Running the Test Suite
Execute the automated test suite with pytest:
```powershell
python -m pytest -v tests/
```

---

## Repository Structure

```
Honeytoken-Based-Insider-Threat-Detector/
├── backend/
│   ├── core/           # Application configuration & settings
│   ├── db/             # SQLAlchemy engine, base & session manager
│   ├── models/         # ORM models (HoneyToken, TokenTrigger, AlertLog)
│   ├── routes/         # API endpoints (/api/v1/tokens, /beacon)
│   ├── schemas/        # Pydantic validation & response schemas
│   └── main.py         # FastAPI application entrypoint
├── decoys/             # Sample decoy templates and configurations
├── docs/               # Architecture documents and data contracts
├── tests/              # Pytest test cases and client fixtures
├── .env.example        # Environment variables template
├── .gitignore          # Git ignore rules
├── Plan.md             # 5-Week implementation plan
├── README.md           # Project documentation
├── requirements.txt    # Python dependencies
└── seed_test_data.py   # Test data generator script
```

---

## Ethical & Scope Consideration
This system is strictly intended for internal enterprise defense and research within infrastructure owned and managed by the deploying organization, in accordance with applicable workplace-monitoring policies and employee consent agreements.
