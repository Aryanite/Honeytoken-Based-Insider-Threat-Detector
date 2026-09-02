# Project Implementation Plan: Honeytoken-Based Insider Threat Detector
**Degree Track:** Bachelor of Technology in Computer Science and Engineering
**Institution:** School of Computer Science and Engineering, IILM University, Greater Noida
**Academic Session:** 2026–27
**Supervisor:** Mr. Atul Kumar Singh
**Team Members:**
- Aryan Singh (2410031399)
- Aniket Tiwari (2410031403)
- Sana Khan (2410031378)
- Saumya Kashyap (2410031737)

---

## 1. Project Overview & Target Objectives

Traditional perimeter security tools and firewalls are built to catch external attackers, so they fail when malicious actions are carried out by someone using legitimate, authorized credentials from inside the organization. This project implements a deception-based insider threat detection prototype designed to solve two core limitations of existing tools:
1. **Multi-Type Decoy Generation:** Generation of multiple honeytoken formats (API keys, canary documents, database records) via a centralized platform.
2. **Dynamic Risk-Level Alert Labeling:** Automated triage replacing flat, unprioritized alerts with dynamic categorization (Low, Medium, High, Critical) based on asset sensitivity, access frequency, and context.

**Scope & ethics note:** This tool is intended for use on infrastructure the deploying organization owns/controls, under an existing workplace-monitoring or acceptable-use policy. The final report should include a short paragraph on this scope, since deception-based monitoring of real users has legal/consent implications outside a lab or authorized-pentest context.

---

## 2. Technical Stack & Architecture

### Technology Selection
- **Backend API & Webhooks:** Python / FastAPI (asynchronous route handling, automatic OpenAPI/Swagger generation)
- **Database Layer:** SQLite (local development) / PostgreSQL with SQLAlchemy ORM
- **Frontend Dashboard:** React + Tailwind CSS (or lightweight HTML5/Tailwind with Server-Sent Events)
- **Decoy Generation Tools:** `python-docx` for document manipulation, standard cryptography/secrets libraries for API token synthesis
- **Testing & Verification:** `pytest`, `pytest-asyncio`, `httpx`
- **Config/Secrets:** `python-dotenv` for local secrets, `.env.example` committed instead of real `.env`

### System Architecture Pipeline

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

## 3. 5-Week Sprint Timeline & Work Breakdown

### Week 1: Foundations, Architecture & Data Modeling
*Focus: Git workflow, database ORM mapping, core API contracts, and beacon listener foundation.*

**Kickoff (Day 1, 15 min, all four) — sets the contract so nobody has to wait on anybody else:**
Agree on and write down in `/docs/contract.md`: (1) the token record's field names — `token_id` (UUID), `token_type`, `criticality` (1–50), `status`; (2) the response envelope shape — `{status, data, error}`; (3) the base route prefix `/api/v1`. This one document is the only cross-person dependency all week — everyone codes against it, not against each other's in-progress code.

- **Aryan Singh (Backend Lead & Architecture)** — owns `/backend/models/`, `/backend/db/`
  - Initialize the Git repository, project structure (`/backend`, `/tests`, `/docs`), and Python virtual environment setup.
  - Implement SQLAlchemy ORM models: `HoneyToken`, `TokenTrigger`, `AlertLog` with primary/foreign keys, indexes, and cascades — built directly from the agreed field contract, no dependency on anyone else's code.
  - Configure database session management (`db/session.py`) and SQLite/PostgreSQL engine connection.
  - Implement core FastAPI CRUD endpoints (`POST /api/v1/tokens`, `GET /api/v1/tokens`, `DELETE /api/v1/tokens/{token_id}`) using simple inline validation for now; swap in Sana's Pydantic schemas in a 10-minute merge once both are ready.
  - Set up `.env.example` / config separation for secrets management.
  - *Independent because:* works entirely inside `/backend/models/` and `/backend/db/`, files no one else touches this week.

- **Aniket Tiwari (Listener Engine & Automated Testing)** — owns `/backend/routes/beacon.py`, `/tests/`
  - Build the telemetry receiver route `GET /beacon/{token_id}` against a small in-memory mock token store (a Python dict matching the field contract) — this means he never has to wait for Aryan's real database to exist.
  - Implement the request-extraction helper to parse source IP (handling `X-Forwarded-For`), `User-Agent`, and serialize headers — a pure function, fully standalone and independently testable.
  - Configure the listener's return payload (transparent 1x1 GIF byte array) so it never throws on the client side.
  - Build the `pytest` + `httpx.AsyncClient` testing harness and a `seed_test_data.py` seeder, run against the mock store all week.
  - **End-of-week integration (Friday, ~15 min pairing with Aryan):** swap the mock store for Aryan's real ORM session — the only moment this role touches someone else's code.
  - *Independent because:* the mock store means the whole route + extraction logic + test suite can be built and tested without the real DB existing yet.

- **Sana Khan (Validation Schemas & API Documentation)** — owns `/backend/schemas/`
  - Define Pydantic request/response schemas — `TokenCreateSchema`, `TokenResponseSchema`, `TriggerLogResponseSchema` — directly from the field contract; schemas are pure data classes, so this needs no endpoint to exist yet.
  - Implement input sanitization and validation rules (allowed token types, string constraints, criticality range 1–50).
  - Write the `beacon_url` builder helper (base host + UUID) — a standalone pure function.
  - Build a shared error-response formatting utility (`400`/`422` shapes) that Aryan's endpoints import later, not the other way around.
  - **Friday only:** once Aryan's CRUD endpoints exist, spend ~30 minutes wiring these schemas in and documenting them in Swagger (`/docs`). Until then, draft the parameter/response tables offline from the contract doc.
  - *Independent because:* schemas, validators, and the URL/error helpers are all standalone modules; only the final Swagger wiring touches shared code, and it's scheduled last.

- **Saumya Kashyap (Decoy Artifact Templates & Team Onboarding)** — owns `/decoys/`, `/docs/README.md`
  - Assemble mock configuration decoy files (`.env`, `credentials.json`, `config.yaml`) with placeholder credentials.
  - Create raw canary document templates (a `.docx` containing placeholder tracking pixel links).
  - Write helper scripts to synthesize realistic high-entropy strings (mock AWS keys, Stripe-formatted tokens).
  - Author the `README.md` (environment setup, dependency install, local server startup, `requirements.txt`).
  - Verify mock decoys match normal workplace file conventions to preserve deception efficacy.
  - *Independent because:* this entire track lives in its own `/decoys/` folder and touches no shared code path all week.

*Only real dependency this week: the Friday integration pairing between Aniket and Aryan (swap mock store → real DB) and Sana's Friday Swagger pass. Everything else can be built, run, and tested in isolation from Day 1.*

---

### Week 2: Decoy Generator Engines & Telemetry Listeners
*Focus: Automated canary generation pipelines and realistic attack targets.*

- **Aryan Singh**
  - Implement database honeytoken detection: design a decoy table (e.g., `payroll_records_decoy`) with an access-logging proxy or DB trigger.
  - Integrate decoy generator service logic into the existing FastAPI backend routes.
  - Add basic admin authentication (API key or session-based) gating all `/api/v1/*` write and dashboard routes — kept minimal but present for the prototype.

- **Aniket Tiwari**
  - Develop the automated Canary Document Generator using `python-docx` to embed tracking pixel tags linked to unique `token_id`s.
  - Build the PDF canary generator using stream injection (URI actions/remote images).
  - Build the mock credential verification endpoint: `POST /api/v1/auth/verify` to capture rogue API key usage attempts.
  - Expand test suites to verify tracking pixel fires and payload extraction across simulated HTTP clients.

- **Sana Khan**
  - Design schemas/endpoints for tracking generated decoy artifacts: `GET /api/v1/tokens/{token_id}/download`.
  - Standardize logging data structures so canary-doc triggers and API-key hits output a consistent JSON telemetry format.
  - Validate query parameter parsing for the credential verification endpoint.

- **Saumya Kashyap**
  - Build contextual file injection helpers: realistic file paths, fake folder structures, believable dummy data (employee names, mock compensation bands).
  - Test opening generated canary Word documents across different word processors to verify silent outbound beacon requests.
  - Maintain a library of pre-built decoy templates for one-click deployment.

---

### Week 3: Dynamic Risk-Scoring Engine & Real-Time Alerts
*Focus: Algorithm development, alert prioritization, and live event streaming.*

- **Aryan Singh**
  - Implement the core scoring algorithm:
    $$\text{Final Risk Score} = W_{\text{asset}} \times C_{\text{access}} \times F_{\text{frequency}}$$
  - Build rolling-window frequency calculation (hits within the last 5 minutes from the same IP or token).
  - Implement automated severity labeling: 0–25 Low, 26–50 Medium, 51–75 High, 76+ Critical.

- **Aniket Tiwari**
  - Implement real-time event streaming: FastAPI WebSocket or SSE route `GET /api/v1/stream/alerts`.
  - Build event dispatch triggers that broadcast newly scored alerts immediately on database insertion.
  - Add basic rate-limiting to the public `/beacon/{token_id}` endpoint so it can't be trivially flooded.
  - Write automated stress tests simulating simultaneous decoy hits to verify algorithm stability under rapid triggering.

- **Sana Khan**
  - Implement contextual timestamp evaluation: flag access outside business hours (8:00 AM–7:00 PM local) or on weekends, applying a 1.5× multiplier.
  - Define schemas for outbound alert payloads, with score-breakdown factors explicit for dashboard analysts.
  - Write unit tests for edge-case calculations (single hits vs. bursts).

- **Saumya Kashyap**
  - Configure external alerting integrations (email or mock Slack/Discord webhook for `Critical` severity alerts).
  - Assemble test cases comparing expected vs. actual scores across decoy types and hit frequencies.
  - Document the risk-scoring parameters and modifier rationale for the final report.

---

### Week 4: Admin Dashboard & Frontend Integration
*Focus: Graphical interface for decoy creation, incident tracking, and status monitoring.*

- **Aryan Singh**
  - Build backend aggregation routes: `GET /api/v1/dashboard/stats` (active tokens, total triggers, severity breakdown).
  - Finalize CORS configuration and security middleware for the frontend.
  - Integrate the Week-2 admin auth into the dashboard's login flow.

- **Aniket Tiwari**
  - Build the Live Incident Monitor view: real-time event log with color-coded severity badges (Green/Yellow/Orange/Red); expandable cards showing source IP, User-Agent, timestamp, and score breakdown.
  - Integrate WebSocket/SSE connection handlers so the UI updates without manual reloads.

- **Sana Khan**
  - Build the Token Management table: searchable list with filtering by status (`active`/`revoked`) and type; deactivation buttons wired to `DELETE /api/v1/tokens/{token_id}`.
  - Create dashboard metric cards (Active Decoys, Today's Triggers, Critical Threats).

- **Saumya Kashyap**
  - Implement the Token Factory form: token name, decoy type dropdown, placement location.
  - Wire the form to trigger downloads of generated decoy files / display generated fake credentials.
  - Audit UI layout, typography, and responsive styling.

---

### Week 5: Attack Simulation, Benchmarking & Final Documentation
*Focus: End-to-end testing, empirical validation, and report completion.*

- **Aryan Singh**
  - Execute end-to-end threat simulation scenarios (API key in `.env`, unauthorized curl request, canary payroll document access).
  - Measure detection latency (decoy trigger → live dashboard alert).
  - Author the **System Design & Implementation** chapter of the final report.

- **Aniket Tiwari**
  - Write reproducible simulation scripts (`simulate_attacks.py`) covering single ping, off-hours hit, and rapid multi-access bursts.
  - Validate scoring accuracy and verify zero false negatives during simulated runs.
  - Author the **Testing, Simulation & Verification** chapter of the final report.
  - Prepare and record the video walkthrough of the working system.

- **Sana Khan**
  - Aggregate performance/evaluation metrics into comparison tables and charts (detection speed, classification distribution).
  - Write the **Results, Discussion & Performance Analysis** chapter.
  - Final code cleanup: remove debug logging, format docstrings across modules.

- **Saumya Kashyap**
  - Format the complete Final Major Project Report per university guidelines (Candidate Declaration, Certificates, Literature References).
  - Write the short **Scope & Ethical Considerations** section (monitoring-policy/consent framing from Section 1).
  - Prepare the PowerPoint defense slides (objectives, modular architecture, risk categorization advantages).
  - Verify the repo `README.md` includes complete setup, API contracts, and reproduction steps.

---

## 4. Evaluation & Acceptance Criteria

1. **Multi-Format Generation:** The dashboard must generate at least three distinct decoy types — canary DOCX files, synthetic API keys, and database canary entries.
2. **Deterministic Trigger Capture:** Accessing any deployed token must reliably log source IP, User-Agent, and timestamp without client-side crashes.
3. **Multi-Tier Classification:** The scoring engine must dynamically differentiate Low/Medium/High/Critical alerts based on defined weights and access patterns, not flat binary alerts.
4. **Real-Time Notification:** Alert events must appear on the admin interface within under 2 seconds of decoy access.
5. **Access Control:** Dashboard and token-management routes must require authentication; only the beacon endpoint remains intentionally public.