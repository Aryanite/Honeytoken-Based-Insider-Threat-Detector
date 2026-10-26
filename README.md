# CyberGuard SOC: Honeytoken-Based Insider Threat Detector

An enterprise-grade deception grid and real-time incident triage platform designed to detect and isolate malicious insiders and compromised internal credentials. **CyberGuard SOC** replaces flat, unprioritized binary alarms with an automated multi-factor mathematical risk engine that evaluates asset criticality, contextual access anomalies, and burst frequency.

---

### Academic & Institutional Metadata
- **Project Title:** Honeytoken-Based Insider Threat Detector (CyberGuard SOC)
- **Institution:** School of Computer Science and Engineering, IILM University, Greater Noida
- **Degree Track:** Bachelor of Technology in Computer Science and Engineering (2026–27)
- **Supervisor:** Mr. Atul Kumar Singh

### Engineering Team Credits
- **Aryan Singh (2410031399)** — Backend Lead, Architecture & Dynamic Risk Engine
- **Aniket Tiwari (2410031403)** — Listener Engine, Decoy Generation, Alert Streaming & Attack Simulation
- **Sana Khan (2410031378)** — Validation Schemas, API Contracts & Contextual Triage Analytics
- **Saumya Kashyap (2410031737)** — Decoy Artifact Templates, Ethical Framing & Active Containment UI

---

## 1. System Architecture & Telemetry Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       DECEPTION DEPLOYMENT GRID                             │
│  • Binary Canary PDFs (%PDF-1.4 with embedded /OpenAction URI)             │
│  • Canary Word Documents (.docx with remote 1x1 image relationships)        │
│  • Decoy Cloud Credentials (.env / .yaml with synthetic AWS / Stripe keys)  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (Insider Access Attempt)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    COVERT TELEMETRY & TRAP LISTENERS                        │
│  • GET /beacon/<token_id>            ──> 43-byte Transparent 1x1 GIF        │
│  • POST /api/v1/auth/verify          ──> Emulated Cloud Gateway (401 Trapped)│
│  • Sliding-Window Rate Limiter       ──> Anti-DoS Protection               │
│  • Real IP Extractor                 ──> X-Forwarded-For & LAN IP Resolver  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ (Client IP, Headers, Timestamp)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                   DYNAMIC RISK-SCORING ENGINE (W x C x F)                   │
│   Final Score = W(asset) × C(context) × F(frequency)                        │
│   • Asset Sensitivity Weight (W): 1.0 to 50.0                               │
│   • Context Multiplier (C): Business Hours (1.0x) vs Off-Hours/CLI (1.8x)   │
│   • Frequency Multiplier (F): 1 hit (1.0x) to >=5 hits burst (1.8x)         │
│   • Triage: Low (<=25) | Medium (26-50) | High (51-75) | Critical (>75)    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
┌──────────────────────────────────────┐┌─────────────────────────────────────┐
│     SQLITE AUDIT PERSISTENCE         ││      REAL-TIME DISPATCH             │
│  • events table (telemetry + score)  ││  • Server-Sent Events (SSE Stream)  │
│  • blocked_ips (quarantine registry) ││  • Polling JSON API Reconciliation │
└──────────────────────────────────────┘└─────────────────┬───────────────────┘
                                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CYBERGUARD ADMIN SOC CONSOLE                        │
│  • Live Incident Feed with dynamic Risk Score Chips & Severity Badges       │
│  • One-Click Quarantining (/api/block-ip) & Token Revocation (/api/revoke)  │
│  • Asset Frequency Analytics Chart & Inventory Management                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Dynamic Risk Scoring Engine ($W \times C \times F$)

Traditional intrusion detection generates flat alerts that cause alarm fatigue. CyberGuard SOC evaluates every trigger dynamically:

$$\text{Final Risk Score} = W_{\text{asset}} \times C_{\text{access}} \times F_{\text{frequency}}$$

### Factor 1: Base Asset Sensitivity Weight ($W_{\text{asset}}$ — range `1.0` to `50.0`)
- **Cloud Secrets & Environment Files** (`.env`, `aws`, `stripe`, `key`, `secret`, `config.yaml`): **`45.0`**
- **Executive & Financial Records** (`.pdf`, `payroll`, `salary`, `financial`): **`35.0`**
- **Board Strategy & HR Memoranda** (`.docx`, `strategy`, `hr`, `confidential`): **`30.0`**
- **Default Telemetry Beacon / URL Token**: **`25.0`**

### Factor 2: Context Multiplier ($C_{\text{access}}$)
- **Normal Business Hours** (Mon–Fri, 08:00 to 18:59 local): **`1.0x`**
- **Off-Hours / Weekend Access** (< 08:00, >= 19:00, or Saturday/Sunday): **`1.5x`**
- **Automated CLI / Pentest Tooling** (`curl`, `python-requests`, `urllib`, `postman`, `nmap`, `sqlmap`, `nikto`, `wget`, `httpx`, `burp`): **`1.2x`**
- **Compound After-Hours CLI Attack**: **$1.5 \times 1.2 = 1.8\times$**

### Factor 3: Burst Frequency Multiplier ($F_{\text{frequency}}$ — 5-minute sliding window)
- **1 hit** (Isolated reconnaissance attempt): **`1.0x`**
- **2 to 4 hits** (Active manual directory exploration): **`1.3x`**
- **$\ge$ 5 hits** (Automated script or credential stuffing burst): **`1.8x`**

### Triage Severity Classification
| Risk Score Range | Severity Tier | SOC Response Recommendation |
|---|---|---|
| `0.0` – `25.0` | **Low** | Routine logging, benign access verification |
| `25.1` – `50.0` | **Medium** | Automated monitoring; review access privileges |
| `50.1` – `75.0` | **High** | Alert on-duty SOC analyst; verify employee location |
| `> 75.0` | **Critical** | Immediate host quarantine & workstation isolation |

---

## 3. Core API Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/beacon/<token_id>` | `GET` | Public | Covert listener returning 43-byte transparent GIF; calculates risk score and records incident telemetry. |
| `/api/v1/auth/verify` | `POST` | Public | Honeypot cloud IAM validation gateway; traps fake API keys with realistic HTTP `401 Unauthorized`. |
| `/api/v1/stream/alerts` | `GET` | Public | Server-Sent Events (SSE) stream pushing sub-millisecond incident alerts directly to the dashboard. |
| `/api/dashboard-data` | `GET` | Admin | Complete JSON reconciliation payload containing metrics, incidents, resources, and quarantined IPs. |
| `/api/block-ip` | `POST` | Admin | Quarantines a malicious workstation IP; subsequent access attempts receive HTTP `403 Forbidden`. |
| `/api/unblock-ip` | `POST` | Admin | Releases a workstation from quarantine. |
| `/api/revoke-token` | `POST` | Admin | Decommissions a honeytoken; subsequent accesses return GIF silently with zero false-positive alerts. |
| `/generate-file-token` | `GET` | Admin | Generates unique binary PDF, DOCX, or credential decoys with embedded traps. |
| `/health` | `GET` | Public | Health and network status check returning LAN IP. |

---

## 4. Quickstart Guide (Presentation & Demonstration)

### 1. Installation
Clone the repository and install dependencies in Python 3.10+:
```powershell
pip install -r requirements.txt
```

### 2. Running the SOC Application
Start the CyberGuard SOC server:
```powershell
python app/app.py
```
Terminal will output:
```
=======================================================
🛡️  CYBERGUARD SOC: HONEYTOKEN-BASED INSIDER THREAT DETECTOR
=======================================================
Local Console: http://127.0.0.1:5000/dashboard
LAN Gateway:   http://192.168.x.x:5000
Admin Portal:  /admin/login
User Portal:   /user-dashboard
=======================================================
```
- **Default Admin Credentials:** Username: `admin` | Default password auto-generated in terminal on first run or set via `CYBERGUARD_ADMIN_PASSWORD`.

### 3. Running the Attack Simulator
In a separate terminal, launch the autonomous threat simulation suite:
```powershell
python simulate_attacks.py
```
This simulates 4 realistic insider threat scenarios:
1. **Curious Insider:** Standard document open with browser user-agent.
2. **Malicious Engineer:** CLI cloud credential probe against `/api/v1/auth/verify`.
3. **Automated Recon Burst:** 5 rapid requests triggering the $1.8\times$ frequency multiplier into **CRITICAL** severity.
4. **Revoked Token Probing:** Verification of zero false-positive alerts on decommissioned tokens.

### 4. Running the Automated Pytest Suite
Execute all 58 automated integration and security tests:
```powershell
pytest -v
```

---

## 5. Repository Structure & Documentation Index

```
Honeytoken-Based-Insider-Threat-Detector/
├── .env.example              ← Environment template for secrets and config
├── .gitignore                ← Standard git ignore rules (caches, DBs, test artifacts)
├── pytest.ini                ← Pytest configuration file
├── requirements.txt          ← Python dependency specifications
├── README.md                 ← Master project README with architecture, quickstart, & docs index
├── simulate_attacks.py       ← Threat actor simulation harness & micro-latency benchmarker
├── seed_test_data.py         ← Initial database seeder for development & demonstrations
├── honeytoken.db             ← Local development database (SQLAlchemy)
│
├── app/                      ← CyberGuard SOC Flask application (runtime, routing, auth)
├── backend/                  ← FastAPI REST service (ORM models, routers, schemas, services)
├── database/                 ← SQLite persistence layer (events.db, migrations, admin auth)
├── alerts/                   ← Dynamic risk scoring engine (W x C x F) & alert manager
├── honeytokens/              ← Multi-format decoy generators (PDF, DOCX, ENV) & tokens.json
├── detection/                ← Anti-DoS sliding-window rate limiter & telemetry detection
├── decoys/                   ← Decoy configuration and credential templates
├── decoy_files/              ← Synthesized binary decoy artifacts (.pdf, .docx, .env)
├── templates/                ← Jinja2 HTML templates for CyberGuard SOC UI
├── static/                   ← Modern dark-mode stylesheets & CSS tokens
├── frontend/                 ← SPA web interface for FastAPI
├── tests/                    ← 58 automated unit, integration, stress, and schema tests
│
└── docs/                     ← Standardized, organized documentation tree
    ├── README.md             ← Master Documentation Catalog & Reading Guide
    ├── architecture/         ← Core technical design & system diagrams
    │   ├── MODEL_ARCHITECTURE_AND_FLOWCHART.md
    │   └── contract.md
    ├── presentation/         ← Presentation & demonstration materials
    │   ├── EXPLANATION_FOR_SIR.md
    │   └── flowchart_viewer.html
    ├── evaluation/           ← Empirical benchmarks, metrics, & latency analysis
    │   └── performance_and_evaluation.md
    ├── team/                 ← Individual engineering logs for all 4 team members
    │   ├── Aryan_Work.md     (2410031399 — Backend Lead & Architecture)
    │   ├── Aniket_Work.md    (2410031403 — Listener Engine & Simulation Lead)
    │   ├── Sana_Work.md      (2410031378 — Schemas & Triage Analytics Lead)
    │   └── Saumya_Work.md    (2410031737 — Decoy Templates & Containment Lead)
    └── plans/                ← Project engineering roadmaps & specifications
        ├── finalplan.md
        ├── Plan.md
        └── honeytoken-insider-threat-detector-plan.md
```

### Complete Documentation Index:
- [**Documentation Catalog**](docs/README.md) — Comprehensive guide to all technical and academic documentation.
- [**System Model Architecture & Detailed Flowchart**](docs/architecture/MODEL_ARCHITECTURE_AND_FLOWCHART.md) — Detailed 8-layer architecture, Mermaid flowcharts, and risk formula.
- [**Executive Presentation Guide**](docs/presentation/EXPLANATION_FOR_SIR.md) — Layer-by-layer technical breakdown prepared for faculty evaluation.
- [**Interactive Flowchart Viewer**](docs/presentation/flowchart_viewer.html) — Standalone HTML visualizer for the end-to-end telemetry flowchart.
- [**Performance & Latency Evaluation**](docs/evaluation/performance_and_evaluation.md) — Empirical micro-latency benchmarks and rate-limiting stress analysis.
- [**Engineering Team Logs**](docs/team/) — Individual work records for [Aryan Singh](docs/team/Aryan_Work.md), [Aniket Tiwari](docs/team/Aniket_Work.md), [Sana Khan](docs/team/Sana_Work.md), and [Saumya Kashyap](docs/team/Saumya_Work.md).

---

## 6. Ethical Scope & Authorization Statement

This prototype is engineered strictly for authorized defensive cybersecurity monitoring, educational research, and internal network defense on infrastructure owned or controlled by the deploying organization. Active deception-based monitoring must comply with workplace acceptable-use policies and applicable legal frameworks.

