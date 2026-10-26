# MASTER AGENT DIRECTIVE: End-to-End Transformation & Verification into "Honeytoken-Based Insider Threat Detector (CyberGuard SOC)"

## 1. ROLE & OBJECTIVE
You are an autonomous Principal Security Software Engineer operating inside this workspace. 
Your objective is to refactor, upgrade, and completely rebrand the existing baseline codebase (legacy Flask prototype) into our final target system: **"Honeytoken-Based Insider Threat Detector (CyberGuard Admin SOC)"**.

### Academic & Project Metadata (Use for README & UI Headers):
- **Project Title:** Honeytoken-Based Insider Threat Detector (CyberGuard SOC)
- **Institution:** School of Computer Science and Engineering, IILM University, Greater Noida — B.Tech CSE (2026–27)
- **Supervisor:** Mr. Atul Kumar Singh
- **Team Members:**
  - Aryan Singh (2410031399) — Backend Lead, Architecture & Dynamic Risk Engine
  - Aniket Tiwari (2410031403) — Listener Engine, Decoy Generation, Alert Streaming & Attack Simulation
  - Sana Khan (2410031378) — Validation Schemas, API Contracts & Contextual Triage Analytics
  - Saumya Kashyap (2410031737) — Decoy Artifact Templates, Ethical Framing & Active Containment UI

---

## 2. ANTI-HALLUCINATION & EXECUTION RULES (STRICT)
1. **READ BEFORE EDITING:** Never guess file contents, variable names, or SQLite table schemas. Always inspect the existing file (`app/app.py`, `database/database.py`, `honeytokens/file_honeytoken.py`, `templates/dashboard.html`, etc.) before modifying it.
2. **DO NOT BREAK WORKING INFRASTRUCTURE:** Keep the working Flask runtime, SQLite database engine (`database/database.py`), Werkzeug authentication (`database/admin_auth.py`), LAN IP resolver, and IP Blocklist (`blocked_ips`) intact. Build the new features ON TOP of this working foundation so nothing breaks.
3. **ZERO TRACES OF LEGACY BRANDING:** By the end of execution, a case-insensitive grep for legacy prototype names across the entire codebase (HTML, CSS, Python, Markdown) MUST return `0` matches.
4. **MANDATORY VERIFICATION GATES:** At the end of every phase below, you MUST run the specified shell/python verification command. Do not proceed to the next phase until the verification command passes with exit code `0`.

---

## 3. STEP-BY-STEP IMPLEMENTATION PLAN

### PHASE 1: Workspace Audit & Baseline Inspection
1. List all files in the workspace and inspect:
   - `app/app.py`
   - `database/database.py`
   - `alerts/alert_manager.py`
   - `detection/detector.py`
   - `honeytokens/generator.py` and `honeytokens/file_honeytoken.py`
   - All HTML files in `templates/` and CSS in `static/`
2. Check the active Python environment (`python --version` or `venv`) and ensure `flask`, `werkzeug`, and `pytest` are installed.

---

### PHASE 2: Dynamic Multi-Factor Risk Scoring Engine ($W \times C \times F$)
Our core innovation is replacing static binary alerts with a mathematical risk-scoring engine.

1. Create a new module `alerts/risk_scoring.py` (or inside `alerts/alert_manager.py` and re-export) that implements:
   $$\text{Final Risk Score} = W_{\text{asset}} \times C_{\text{access}} \times F_{\text{frequency}}$$
   - **Base Asset Weight ($W_{\text{asset}}$ — range `1.0` to `50.0`):**
     - `.env` / `aws` / `stripe` / `key` / `secret` / `config.yaml` $\rightarrow$ `45.0`
     - `.pdf` / `payroll` / `salary` / `financial` $\rightarrow$ `35.0`
     - `.docx` / `strategy` / `hr` / `confidential` $\rightarrow$ `30.0`
     - Default URL/beacon token $\rightarrow$ `25.0`
   - **Context Multiplier ($C_{\text{access}}$):**
     - Business hours (Mon–Fri, `08:00` to `18:59` local time): `1.0`
     - Off-hours (`< 08:00` or `>= 19:00`) OR Weekend (`weekday() >= 5`): `1.5`
     - Automated CLI / Pentest Tool in `User-Agent` (case-insensitive match for `curl`, `python-requests`, `urllib`, `postman`, `nmap`, `sqlmap`, `nikto`, `wget`, `httpx`, `burp`): multiply by `1.2`
     - Compound off-hours + CLI tool: `1.5 * 1.2 = 1.8`
   - **Frequency Multiplier ($F_{\text{frequency}}$ — based on recent triggers in the last 5 minutes from the same IP or token):**
     - `1` hit: `1.0`
     - `2` to `4` hits: `1.3`
     - `>= 5` hits: `1.8`
   - **Severity Triage Classification:**
     - `0.0 <= score <= 25.0` $\rightarrow$ `"Low"`
     - `25.0 < score <= 50.0` $\rightarrow$ `"Medium"`
     - `50.0 < score <= 75.0` $\rightarrow$ `"High"`
     - `score > 75.0` $\rightarrow$ `"Critical"`

2. **Database Integration (`database/database.py`):**
   - Inspect `events` table creation in `database/database.py`.
   - Safely add `risk_score REAL DEFAULT 0.0` and `severity TEXT DEFAULT 'High'` columns (use `ALTER TABLE` inside a `try/except` block on startup AND include them in `CREATE TABLE IF NOT EXISTS events` so both existing and fresh databases work seamlessly).
   - Return `risk_score` and `severity` in the event dictionaries returned to `/api/dashboard-data`.
   - Also count how many events occurred in the last 5 minutes from the triggering IP (`get_recent_hit_count(ip, minutes=5)`) so `F_frequency` is dynamically calculated on every hit!

3. **Phase 2 Verification Gate:**
   - Run a one-line python command to verify:
     `python -c "from alerts.risk_scoring import calculate_risk_score; res = calculate_risk_score('aws_prod.env', 'curl/8.4.0', recent_hits=5, force_off_hours=True); assert res['risk_score'] > 75 and res['severity'] == 'Critical', res; print('PHASE 2 VERIFIED:', res)"`

---

### PHASE 3: Multi-Format Native Decoy Generators & Covert Traps
Upgrade decoy generation and listeners so the project fulfills every core technical promise:

1. **Native Binary Canary PDF Generator (`honeytokens/file_honeytoken.py`):**
   - When the requested decoy filename ends with `.pdf`, do NOT write plain ASCII text. Write a valid binary `%PDF-1.4` file with an embedded `/Catalog` containing `/OpenAction << /Type /Action /S /URI /URI (http://<server_ip>:5000/beacon/<token_id>) >>` AND a visible page stream displaying confidential financial/payroll decoy text.
2. **Canary DOCX & Credential Templates (`honeytokens/file_honeytoken.py`):**
   - When the filename ends with `.docx`, generate a realistic Word-compatible document (using `python-docx` if installed, or an MHTML/Word XML document with an external image/template relationship pointing to `http://<server_ip>:5000/beacon/<token_id>`) so opening it in Word triggers the beacon.
   - When the filename ends with `.env`, `.yaml`, or `.yml`, generate realistic high-entropy decoy cloud credentials (`AWS_ACCESS_KEY_ID=AKIA...`, `STRIPE_LIVE_SECRET=sk_live_...`) along with `INTERNAL_AUTH_VERIFY_ENDPOINT=http://<server_ip>:5000/api/v1/auth/verify` and `BEACON_HEALTH_URI=http://<server_ip>:5000/beacon/<token_id>`.
3. **Covert 1x1 GIF Beacon Route (`GET /beacon/<token_id>` in `app/app.py`):**
   - Add route `@app.route("/beacon/<token_id>", methods=["GET"])` alongside the existing `/honeytoken/<token_id>` and `/user/file/<token_id>` routes.
   - Extract client IP (check `X-Forwarded-For` first, then fallback to `request.remote_addr` and existing LAN IP resolution).
   - Check if IP is blocked (`is_ip_blocked`).
   - If the token exists and is not `REVOKED`, log the telemetry + dynamic risk score to SQLite and mark token as `TRIGGERED`.
   - Return a 43-byte base64-decoded transparent `GIF89a` (`R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7`) with `mimetype="image/gif"` and headers `Cache-Control: no-cache, no-store, must-revalidate`.
4. **Honeypot Cloud Auth Gateway (`POST /api/v1/auth/verify` in `app/app.py`):**
   - Add route `@app.route("/api/v1/auth/verify", methods=["POST"])`.
   - Extract any `Authorization: Bearer <token>` header or JSON payload, log an incident with asset weight `45.0` (Cloud API Key Probe) and calculate risk score.
   - Return HTTP `401` with header `WWW-Authenticate: Bearer error="invalid_token"` and JSON:
     `{"status": "error", "data": null, "error": "The provided credentials are invalid, revoked, or lack necessary IAM privileges."}`
5. **Token Revocation Support (`POST /api/revoke-token` in `app/app.py`):**
   - Allow admins to revoke a token (`status = "REVOKED"` in `tokens.json`). If a `REVOKED` token hits `/beacon/<token_id>`, return the 1x1 GIF silently without logging a false-positive alert.
6. **Sliding-Window Rate Limiter (`detection/rate_limiter.py`):**
   - Add an in-memory sliding-window rate limiter (max 30 requests per 60 seconds per IP on `/beacon/<token_id>`) so DoS floods are throttled safely.

7. **Phase 3 Verification Gate:**
   - Verify PDF header bytes, `/beacon/<token_id>` 43-byte GIF response, and `/api/v1/auth/verify` 401 JSON response using Flask's `app.test_client()`.

---

### PHASE 4: Complete UI Whitewashing & CyberGuard SOC Upgrade
Inspect all files in `templates/` (`admin_login.html`, `dashboard.html`, `user_dashboard.html`, `file_accessed.html`) and `static/style.css`.

1. **Eliminate All Legacy Prototype Branding:**
   - Replace every occurrence of legacy prototype names or `Canary Token Active Honey Token Deception System` with:
     - Main Brand: **CyberGuard SOC**
     - Full Title: **CyberGuard — Honeytoken-Based Insider Threat Detector**
     - Subtitle: **Dynamic Multi-Factor Risk Scoring & Active Deception Grid**
   - Update terminal alert banner in `alerts/alert_manager.py` to:
     `🚨 [CYBERGUARD-SOC] INSIDER THREAT HONEYTOKEN TRIGGERED | Risk Score & Telemetry Logged 🚨`
2. **Display Risk Score & Severity Badges on the SOC Dashboard (`templates/dashboard.html`):**
   - In the Live Incident Log table in `templates/dashboard.html`, add columns for **Risk Score** and **Severity** (with color-coded badges: Critical = Red, High = Orange, Medium = Yellow, Low = Blue/Green).
   - Ensure the JavaScript rendering `/api/dashboard-data` populates `event.risk_score` and `event.severity` in every row.
   - Also add `GET /api/v1/stream/alerts` (SSE endpoint) AND keep `/api/dashboard-data` working so both streaming and polling clients work flawlessly.
3. **Pre-Seed Realistic Insider Threat Decoys:**
   - Ensure the decoy generation UI suggests realistic insider targets (`Executive_Payroll_2026.pdf`, `M&A_Board_Strategy.docx`, `aws_prod_credentials.env`).

---

### PHASE 5: Attack Simulator (`simulate_attacks.py`) & Automated Pytest Suite (`tests/`)
1. **Create `simulate_attacks.py` in the project root:**
   - Must work standalone (`python simulate_attacks.py`) against a running server OR auto-seed a demo token if none is specified.
   - Executes 4 distinct insider threat scenarios and prints a clean forensic table in the terminal:
     1. *Scenario 1: Curious Insider — Standard Document Open (Browser User-Agent)*
     2. *Scenario 2: Malicious Engineer — CLI Credential Probe (`curl/8.4.0` against `/api/v1/auth/verify`)*
     3. *Scenario 3: Automated Recon Burst — 5 rapid hits (`python-requests/nmap` triggering the `1.8x` frequency multiplier -> `CRITICAL` severity)*
     4. *Scenario 4: Revoked Token Check — Verifying zero false-positive alerts on revoked tokens*
2. **Create Comprehensive Pytest Suite (`tests/test_cyberguard.py`):**
   - Write automated tests covering:
     - Risk scoring math (Business hours vs. Off-hours, Browser vs. CLI `1.2x`, Burst Frequency `1.0x`/`1.3x`/`1.8x`, Severity thresholds).
     - Native PDF generation (starts with `%PDF-1.4` and contains `/OpenAction`).
     - `.env` credential decoy generation (`AKIA` and `sk_live_`).
     - `GET /beacon/<token_id>` returns HTTP 200, `image/gif`, 43 bytes, and `Cache-Control: no-store`.
     - `POST /api/v1/auth/verify` returns HTTP 401 and `WWW-Authenticate: Bearer`.
     - Revoked token suppression (hitting a revoked token does not increment incident count).
     - Active IP Blocking (`POST /api/block-ip` blocks subsequent access with HTTP 403).
     - Zero legacy branding check (asserts legacy name does not appear in any HTML template or `README.md`).
3. **Rewrite `README.md`:**
   - Replace the old `README.md` completely so it documents **CyberGuard: Honeytoken-Based Insider Threat Detector**, its system architecture diagram, the $W_{\text{asset}} \times C_{\text{access}} \times F_{\text{frequency}}$ formula, the API endpoints (`/beacon/<token_id>`, `/api/v1/auth/verify`, `/api/dashboard-data`, `/api/block-ip`), team member credits, and quickstart commands.

---

### PHASE 6: Final Zero-Trace & End-to-End Verification Gate
Before concluding your task, run ALL of the following checks and show their exact terminal output:
1. `pytest -v` (All tests must PASS).
2. Case-insensitive search across all project files (excluding `.git`) for legacy prototype brand — must return `0` matches.
3. Start or simulate the server and run `python simulate_attacks.py` to verify all 4 attack scenarios log properly into SQLite with calculated Risk Scores and Severities.
4. Provide a concise summary of all modified/created files and the exact 2 commands I need to run tomorrow during my live presentation.