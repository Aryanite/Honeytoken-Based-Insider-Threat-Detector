# Sana Khan — Work Log
**Role:** Validation Schemas, API Documentation & Triage Analytics Lead  
**Team:** Honeytoken-Based Insider Threat Detector  
**Institution:** IILM University, Greater Noida — B.Tech CSE 2026–27  
**Supervisor:** Mr. Atul Kumar Singh  

---

## Project Overview

In this project, traditional perimeter firewalls fail against malicious internal personnel operating with legitimate, authorized credentials. Our system deploys a proactive deception grid: multiple honeytoken formats (synthetic cloud API keys, canary Word/PDF documents, and decoy database entries) are planted across internal repositories, cloud storage buckets, and employee file shares. 

When an internal actor accesses or tests any of these decoy assets, covert telemetry listeners silently capture the accessor's IP address, browser fingerprint, client headers, and timestamp. This telemetry feeds into a **Dynamic Risk-Scoring Engine** that dynamically calculates an analytical threat score based on asset sensitivity, access context (off-hours vs. business hours, weekend vs. weekday, suspicious CLI/scanners), and trigger frequency.

As the **Validation Schemas & API Documentation Lead**, my core responsibilities span:
1. **Pydantic Schema Architecture (`/backend/schemas/`):** Designing bulletproof, strictly typed data validation schemas for token creation, updates, decoy downloads, mock authentication verification, normalized forensic telemetry, and outbound alert payloads.
2. **Contextual Evaluation Engine (`/backend/services/risk_scoring.py`):** Implementing the time-of-access contextual modifier ($C_{\text{access}}$) that detects after-hours access (outside 08:00–19:00) and weekend activity (1.5× multiplier), as well as suspicious CLI/pentest tooling (1.2× multiplier).
3. **Outbound Alert & Telemetry Contracts:** Standardizing forensic logging so canary-doc opens and API-key tests output an identical JSON schema for dashboard analysts and incident responders.
4. **Dashboard Analytics & Token Management Table (`/backend/routes/dashboard.py` & `/frontend/`):** Building aggregation APIs for KPI metric cards (Active Decoys, Today's Triggers, Critical Threats), coupled with a modern, glassmorphic security dashboard featuring real-time Server-Sent Events (SSE).
5. **Comprehensive Automated Test Suite & Empirical Benchmarking:** Authoring unit tests for schema validation and edge-case risk calculations, along with empirical latency benchmarks proving detection speed under 15 ms.

---

## Ownership & Module Layout

Under the team implementation plan, I own the `/backend/schemas/` namespace, lead the contextual evaluation algorithms in `/backend/services/`, and co-engineered the administrative frontend and dashboard routes:

```
backend/
├── schemas/
│   ├── __init__.py          ← Public schema exports
│   ├── envelope.py          ← ApiResponse[T] generic contract envelope
│   ├── token.py             ← Token creation, update, and ORM response schemas
│   ├── trigger.py           ← Trigger log response schemas
│   ├── alert.py             ← Score breakdown and SSE alert payload schemas
│   ├── decoy.py             ← Decoy artifact metadata and download query schemas
│   ├── auth_verify.py       ← Mock credential verification request/response schemas
│   ├── telemetry.py         ← Unified forensic telemetry normalization models
│   └── dashboard.py         ← Executive metric cards & severity breakdown schemas
├── services/
│   └── risk_scoring.py      ← Contextual time evaluation & dynamic risk scoring
├── routes/
│   ├── dashboard.py         ← GET /api/v1/dashboard/stats aggregation endpoint
│   └── alerts.py            ← GET /api/v1/alerts incident query endpoints
frontend/
└── index.html               ← Interactive dark-mode security command center UI
docs/
└── performance_and_evaluation.md ← Empirical benchmarks & triage analysis
tests/
├── test_schemas.py          ← Schema boundary & constraint unit tests
├── test_contextual_evaluation.py ← Business hours, weekends & tooling unit tests
└── test_alerts_endpoint.py  ← Alert querying & filtering integration tests
```

---

## Pydantic Validation Schema Architecture

All data flowing into and out of the REST API must conform to strict data contracts. I developed 8 comprehensive Pydantic schema modules in `/backend/schemas/`:

### 1. Standard API Envelope — [`backend/schemas/envelope.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/backend/schemas/envelope.py)
Provides a generic response envelope `ApiResponse[T]` conforming to the team data contract:
```json
{
  "status": "success | error",
  "data": { ... } | null,
  "error": "Error message" | null
}
```
Includes `success_response(data: T)` and `error_response(message: str)` factory helpers utilized across all API routes.

### 2. Honeytoken Schemas — [`backend/schemas/token.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/backend/schemas/token.py)

| Schema | Purpose & Constraints |
|---|---|
| `TokenCreateSchema` | Validates `POST /api/v1/tokens`. Enforces `name` (1–100 chars), `token_type` literal (`api_key`, `canary_doc`, `db_record`), and asset `criticality` strictly between `1` and `50`. |
| `TokenUpdateSchema` | Validates `PATCH /api/v1/tokens/{token_id}`. Uses `exclude_unset=True` for partial state updates (status, description, placement). |
| `TokenResponseSchema` | Serializes ORM instances to JSON. Automatically computes `beacon_url` and limits recent triggers to the 10 most recent entries. |

Also provides the pure function `build_beacon_url(token_id: str) -> str` which resolves `BEACON_BASE_URL` and formats the covert tracking link.

### 3. Decoy Artifact & Preview Schemas — [`backend/schemas/decoy.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/backend/schemas/decoy.py)

| Schema | Purpose |
|---|---|
| `DecoyDownloadQuerySchema` | Validates `format` query parameter on `GET /api/v1/tokens/{token_id}/download` (restricted to `docx` or `pdf`). |
| `DecoyPreviewDataSchema` | Standardized structure returning text representations of planted credentials, SQL insert statements, or document tracking URLs. |
| `DecoyArtifactMetadataSchema` | Tracks generated decoy metadata: MIME type, file size in bytes, filename, and placement scope. |

### 4. Mock Credential Verification Schemas — [`backend/schemas/auth_verify.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/backend/schemas/auth_verify.py)
Validates payloads submitted to `POST /api/v1/auth/verify`:
- `AuthVerifyRequestSchema`: Accepts `api_key` (candidate credential string) and optional `client_id`.
- `AuthVerifyErrorResponseSchema`: Standardized realistic 401 error envelope returning:
  `"The provided credentials are invalid, revoked, or lack necessary IAM privileges."`
  accompanied by `WWW-Authenticate: Bearer error="invalid_token"`. This ensures rogue internal actors assume the key has merely expired rather than suspecting detection.

### 5. Normalized Forensic Telemetry — [`backend/schemas/telemetry.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/backend/schemas/telemetry.py)
Normalizes access events from all decoy formats into an identical structure:
- `TelemetryPayloadSchema`: Captures `token_id`, `source_ip` (with automatic port stripping and whitespace sanitization), `user_agent`, `headers` dictionary, `trigger_vector` (`beacon_pixel`, `credential_verify`, `database_proxy`, `canary_pdf`), and timezone-aware UTC timestamp.
- `NormalizedTriggerSchema`: Clean internal model mapping trigger telemetry to parent asset metadata.

### 6. Outbound Alert & Score Breakdown Schemas — [`backend/schemas/alert.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/backend/schemas/alert.py)
- `ScoreBreakdownSchema`: Fully exposes all risk factors for dashboard analysts:
  - `asset_weight` ($W_{\text{asset}}$: 1.0–50.0)
  - `context_multiplier` ($C_{\text{access}}$: 1.0×–1.8×)
  - `context_reasons` (List of audit explanations)
  - `frequency_multiplier` ($F_{\text{frequency}}$: 1.0×–1.8×)
  - `frequency_reason` (Audit rationale for burst activity)
  - `recent_hits_in_window` (Hits within 5-minute rolling window)
  - `formula` (Human-readable calculation string)
- `AlertPayloadSchema`: Model for outbound real-time events broadcast over Server-Sent Events (SSE).
- `AlertLogResponseSchema`: ORM serialization model for `GET /api/v1/alerts`.
- `AlertFilterQuerySchema`: Validates query parameters for filtering alerts by severity, token ID, and pagination offsets.

### 7. Dashboard Aggregation Schemas — [`backend/schemas/dashboard.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/backend/schemas/dashboard.py)
- `MetricCardsSchema`: Executive KPI values (`active_decoys`, `total_decoys`, `revoked_decoys`, `today_triggers`, `total_triggers`, `critical_threats`).
- `SeverityBreakdownSchema`: Alert distribution counts (`low`, `medium`, `high`, `critical`).
- `TokenTypeBreakdownSchema`: Inventory counts across `api_key`, `canary_doc`, and `db_record`.
- `RecentAlertSummarySchema`: Compact alert preview items for the live dashboard feed.
- `DashboardStatsSchema`: Unified analytical response for `GET /api/v1/dashboard/stats`.

---

## Contextual Evaluation & Dynamic Scoring Engine

Implemented in [`backend/services/risk_scoring.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/backend/services/risk_scoring.py).

### The Dynamic Scoring Formula

$$\text{Final Risk Score} = W_{\text{asset}} \times C_{\text{access}} \times F_{\text{frequency}}$$

Unlike simple binary tripwires, our engine differentiates casual curiosity from deliberate off-hours exfiltration and rapid automated scripting.

### Contextual Evaluation Rules ($C_{\text{access}}$)

1. **Temporal Evaluation (`evaluate_contextual_time`):**
   - Examines the trigger's UTC timestamp.
   - **Business Hours:** Monday through Friday, 08:00 to 19:00 local/UTC $\to 1.0\times$ multiplier.
   - **Off-Hours Modifier:** Triggered before 08:00 or at/after 19:00 $\to \mathbf{1.5\times}$ multiplier.
   - **Weekend Modifier:** Triggered on Saturday (weekday 5) or Sunday (weekday 6) $\to \mathbf{1.5\times}$ multiplier.
   - Appends detailed audit rationale (e.g., `"Off-hours access modifier applied: Outside business hours (21:30 outside 08:00-19:00) (1.5x)"`).

2. **Automated Tooling Evaluation (`evaluate_user_agent`):**
   - Matches against `SUSPICIOUS_USER_AGENTS`: `curl`, `python-requests`, `httpx`, `postman`, `wget`, `nmap`, `nikto`, `sqlmap`, `insomnia`, `go-http-client`.
   - If an automated scanner or CLI utility is detected $\to \mathbf{1.2\times}$ multiplier.
   - Standard browser user-agents receive $1.0\times$.
   - Compound context multiplier: $C_{\text{access}} = \text{round}(\text{TimeMultiplier} \times \text{ToolMultiplier}, 2)$. For an off-hours curl request, $C_{\text{access}} = 1.5 \times 1.2 = \mathbf{1.8\times}$.

3. **Burst Frequency Evaluation (`evaluate_frequency`):**
   - Queries `TokenTrigger` records for the same `token_id` or `source_ip` within a 5-minute sliding window:
     - 1 hit: $1.0\times$ (isolated access)
     - 2–4 hits: $1.3\times$ (moderate burst probing)
     - $\ge 5$ hits: $1.8\times$ (high-frequency brute-force / automated scraping)

4. **Dynamic Severity Triage (`determine_severity`):**
   - **$0.0 \le \text{Score} \le 25.0$ $\to$ `Low`** (Benign accidental access)
   - **$25.0 < \text{Score} \le 50.0$ $\to$ `Medium`** (Daytime probing of sensitive assets)
   - **$50.0 < \text{Score} \le 75.0$ $\to$ `High`** (Off-hours access or CLI reconnaissance)
   - **$\text{Score} > 75.0$ $\to$ `Critical`** (Automated credential bursts or high-value off-hours compromise)

---

## API Routes & Router Registration

I integrated and standardized endpoints across the FastAPI application in [`backend/routes/`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/backend/routes/):

| Method | Endpoint | Router | Description |
|---|---|---|---|
| `GET` | `/api/v1/dashboard/stats` | `dashboard_router` | Aggregates KPI cards, active/revoked counts, severity distribution, and recent alert events |
| `GET` | `/api/v1/alerts` | `alerts_router` | Historical alert log query endpoint with severity and token filtering |
| `GET` | `/api/v1/alerts/{alert_id}` | `alerts_router` | Detailed analytical view of an individual alert and its factor breakdown |
| `GET` | `/api/v1/tokens/{token_id}/download` | `decoys_router` | Synthesizes and streams binary canary `.docx` or `.pdf` documents with embedded tracking links |
| `GET` | `/api/v1/tokens/{token_id}/decoy-preview`| `decoys_router` | Returns formatted code/payload preview snippets for easy planting |
| `POST`| `/api/v1/auth/verify` | `auth_verify_router`| Mock credential gateway capturing unauthorized API key usage attempts |
| `GET` | `/api/v1/stream/alerts` | `stream_router` | Persistent Server-Sent Events (SSE) stream pushing new alerts in real time |
| `GET` | `/` and `/dashboard` | `main.py` | Serves the interactive security command center web dashboard |

All routes return standardized `ApiResponse[T]` envelopes and are documented interactively in Swagger at `/docs`.

---

## Security Command Center (Dashboard & Token Management UI)

Implemented in [`frontend/index.html`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/frontend/index.html).

Built using modern web design principles (dark mode, glassmorphism, responsive CSS grid, typography from Google Fonts *Plus Jakarta Sans* and *JetBrains Mono*), the dashboard provides complete operational control:

1. **Executive KPI Cards:**
   - **Active Decoys:** Live count of active honeytokens with glowing green status pulse.
   - **Today's Triggers:** Daily incident counter updated in real time.
   - **Critical Threats:** Count of alerts exceeding score 75.0 requiring immediate SOC intervention.
   - **Severity Triage Distribution:** Color-coded distribution badges (Low: Blue, Medium: Yellow, High: Orange, Critical: Red).

2. **Token Management Console:**
   - **Real-Time Search & Filtering:** Dynamic client-side filtering by asset name, UUID, status (`active`/`revoked`), and decoy type (`api_key`, `canary_doc`, `db_record`).
   - **Criticality Visualizer:** Gradient progress bar representing asset sensitivity (1–50).
   - **One-Click Deactivation:** Revoke button wired to `DELETE /api/v1/tokens/{token_id}`.
   - **Preview & Copy Modal:** Instant preview modal displaying exact decoy code snippets with a one-click copy button.
   - **Binary Document Downloads:** Direct links to download synthesized canary `.docx` and `.pdf` files.
   - **Deploy Modal:** Interactive form to register new honeytokens with a live criticality weight slider.

3. **Live Incident Monitor (SSE Stream):**
   - Connects directly to `/api/v1/stream/alerts` using the browser's native `EventSource`.
   - Ingests newly triaged alerts with zero polling delay.
   - Displays severity badges, dynamic risk score, source IP, timestamp, and full formula breakdown.

---

## Automated Test Suite & Deep Verification

I expanded the test suite to **47 automated tests** across 10 test modules in [`tests/`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/tests/), verifying 100% test passage:

### 1. Schema Validation Tests — [`tests/test_schemas.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/tests/test_schemas.py) (12 tests)
- Enforces criticality range constraints: validates 1 and 50; rejects 0 and 51 with `ValidationError`.
- Enforces token types: rejects unknown device types.
- Enforces string constraints: rejects empty names and names exceeding 100 characters.
- Validates beacon URL builder pure function output.
- Validates IP sanitization in `TelemetryPayloadSchema` (stripping port numbers from strings like `10.0.0.1:8080`).
- Validates `ScoreBreakdownSchema`, `DashboardStatsSchema`, and envelope helper factories.

### 2. Contextual Evaluation Unit Tests — [`tests/test_contextual_evaluation.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/tests/test_contextual_evaluation.py) (6 tests)
- Validates standard business hours (Tuesday 09:30 UTC $\to 1.0\times$, Friday 18:59 UTC $\to 1.0\times$).
- Validates weekday morning off-hours (Wednesday 07:45 UTC $\to 1.5\times$).
- Validates weekday night off-hours (Thursday 20:15 UTC $\to 1.5\times$).
- Validates weekend access (Saturday noon $\to 1.5\times$, Sunday midnight $\to 1.5\times$).
- Validates automated tooling detection across `curl`, `python-requests`, `postman`, `sqlmap`, `nmap` ($1.2\times$) vs. standard browsers ($1.0\times$).
- Validates dynamic severity classification boundaries ($0 \le \text{Score} \le 25 \to \text{Low}$, $25 < \text{Score} \le 50 \to \text{Medium}$, $50 < \text{Score} \le 75 \to \text{High}$, $\text{Score} > 75 \to \text{Critical}$).

### 3. Incident Query API Tests — [`tests/test_alerts_endpoint.py`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/tests/test_alerts_endpoint.py) (1 test)
- Validates `GET /api/v1/alerts` and `GET /api/v1/alerts/{alert_id}`.
- Verifies filtering by severity tier and token UUID.
- Verifies 404 error envelope for invalid alert IDs.

### 4. Full Test Suite Execution Summary
```
tests/test_alerts_endpoint.py::test_list_and_get_alerts_endpoints PASSED
tests/test_auth_verify.py::test_auth_verify_active_api_key_creates_trigger_and_alert PASSED
tests/test_auth_verify.py::test_auth_verify_json_payload PASSED
tests/test_auth_verify.py::test_auth_verify_revoked_key_silent PASSED
tests/test_auth_verify.py::test_auth_verify_missing_credential_returns_400 PASSED
tests/test_beacon.py::test_beacon_trigger_active_token PASSED
tests/test_beacon.py::test_beacon_revoked_token_silent PASSED
tests/test_beacon.py::test_beacon_non_existent_token_silent PASSED
tests/test_canary_generators.py::test_generate_canary_docx_structure PASSED
tests/test_canary_generators.py::test_generate_canary_pdf_structure PASSED
tests/test_canary_generators.py::test_download_decoy_endpoint PASSED
tests/test_canary_generators.py::test_download_nonexistent_token_404 PASSED
tests/test_contextual_evaluation.py::test_business_hours_weekday PASSED
tests/test_contextual_evaluation.py::test_off_hours_weekday_morning PASSED
tests/test_contextual_evaluation.py::test_off_hours_weekday_night PASSED
tests/test_contextual_evaluation.py::test_weekend_access PASSED
tests/test_contextual_evaluation.py::test_user_agent_evaluation PASSED
tests/test_contextual_evaluation.py::test_severity_classification_boundaries PASSED
tests/test_risk_scoring.py::test_risk_scoring_standard_business_hours PASSED
tests/test_risk_scoring.py::test_risk_scoring_off_hours_and_curl_multiplier PASSED
tests/test_risk_scoring.py::test_risk_scoring_burst_frequency_escalation PASSED
tests/test_risk_scoring.py::test_evaluate_and_log_alert_persists_record PASSED
tests/test_schemas.py::test_token_create_schema_valid PASSED
tests/test_schemas.py::test_token_create_schema_criticality_boundaries PASSED
tests/test_schemas.py::test_token_create_schema_invalid_token_type PASSED
tests/test_schemas.py::test_token_create_schema_name_validation PASSED
tests/test_schemas.py::test_beacon_url_builder PASSED
tests/test_schemas.py::test_auth_verify_request_schema PASSED
tests/test_schemas.py::test_auth_verify_error_response_schema PASSED
tests/test_schemas.py::test_decoy_download_query_schema PASSED
tests/test_schemas.py::test_telemetry_payload_schema_ip_sanitization PASSED
tests/test_schemas.py::test_score_breakdown_schema PASSED
tests/test_schemas.py::test_dashboard_stats_schema PASSED
tests/test_schemas.py::test_api_response_envelope_helpers PASSED
tests/test_simulation.py::test_scenario_1_single_recon_ping PASSED
tests/test_simulation.py::test_scenario_2_off_hours_document_snooping PASSED
tests/test_simulation.py::test_scenario_3_rapid_credential_burst PASSED
tests/test_simulation.py::test_scenario_4_revoked_token_probing PASSED
tests/test_stream.py::test_event_broadcaster_subscribe_and_receive PASSED
tests/test_stream.py::test_stream_alerts_endpoint_handshake PASSED
tests/test_stress.py::test_sliding_window_rate_limiter_logic PASSED
tests/test_stress.py::test_concurrent_beacon_triggers_stress PASSED
tests/test_tokens.py::test_create_honeytoken_success PASSED
tests/test_tokens.py::test_create_honeytoken_invalid_criticality PASSED
tests/test_tokens.py::test_create_honeytoken_invalid_type PASSED
tests/test_tokens.py::test_list_and_filter_tokens PASSED
tests/test_tokens.py::test_get_single_token PASSED

======================= 47 passed in 4.90s =======================
```

---

## Performance Evaluation & Benchmarking

Detailed in [`docs/performance_and_evaluation.md`](file:///c:/Users/Aniket%20Tiwari/Desktop/Projects/Honeytoken-Based-Insider-Threat-Detector/docs/performance_and_evaluation.md).

### Latency Summary

| Operation | Mean Latency | 99th Percentile | Evaluation |
|---|---|---|---|
| Ingress & Extraction | 0.85 ms | 2.10 ms | Instantaneous |
| Contextual Evaluation | 0.12 ms | 0.35 ms | Negligible overhead |
| Frequency Calculation | 1.84 ms | 4.12 ms | Optimized indexed query |
| Database Persistence | 2.65 ms | 6.80 ms | Thread-safe atomic write |
| SSE Live Dispatch | 0.48 ms | 1.25 ms | Sub-millisecond broadcast |
| **Total End-to-End** | **5.94 ms** | **14.62 ms** | **Far below 2.0s project limit** |

---

## Repository Snapshot

```
Honeytoken-Based-Insider-Threat-Detector/
├── backend/
│   ├── core/
│   │   ├── config.py             ← Environment and server configuration
│   │   └── rate_limiter.py       ← Sliding-window rate limiter
│   ├── db/
│   │   ├── base.py               ← Declarative base
│   │   └── session.py            ← Engine & session management
│   ├── models/
│   │   ├── alert.py              ← AlertLog model
│   │   ├── token.py              ← HoneyToken model (with placement synonym)
│   │   └── trigger.py            ← TokenTrigger model
│   ├── routes/
│   │   ├── __init__.py           ← Router aggregation
│   │   ├── alerts.py             ← GET /api/v1/alerts endpoints
│   │   ├── auth_verify.py        ← POST /api/v1/auth/verify gateway
│   │   ├── beacon.py             ← GET /beacon/{token_id} telemetry receiver
│   │   ├── dashboard.py          ← GET /api/v1/dashboard/stats aggregation
│   │   ├── decoys.py             ← Download & preview endpoints
│   │   ├── stream.py             ← GET /api/v1/stream/alerts SSE stream
│   │   └── tokens.py             ← Honeytoken CRUD endpoints
│   ├── schemas/
│   │   ├── __init__.py           ← Clean exports of all schemas
│   │   ├── alert.py              ← Score breakdown & alert payload models
│   │   ├── auth_verify.py        ← Credential verification models
│   │   ├── dashboard.py          ← Metric cards & severity breakdown models
│   │   ├── decoy.py              ← Decoy download & preview models
│   │   ├── envelope.py           ← ApiResponse[T] envelope
│   │   ├── telemetry.py          ← Normalized forensic telemetry models
│   │   ├── token.py              ← Token create, update, and response models
│   │   └── trigger.py            ← Trigger response schema
│   ├── services/
│   │   ├── canary_doc.py         ← Word .docx generator with tracking pixel
│   │   ├── canary_pdf.py         ← PDF-1.4 generator with URI action
│   │   ├── event_stream.py       ← EventBroadcaster SSE dispatcher
│   │   └── risk_scoring.py       ← Contextual timestamp & risk scoring engine
│   └── main.py                   ← FastAPI entry point & dashboard mounter
├── frontend/
│   └── index.html                ← Interactive cybersecurity command center UI
├── docs/
│   ├── contract.md               ← Baseline team API & data contract
│   └── performance_and_evaluation.md ← Empirical benchmarks & analysis report
├── tests/
│   ├── conftest.py               ← Multi-threaded test harness & fixtures
│   ├── test_alerts_endpoint.py   ← 1 alert query test
│   ├── test_auth_verify.py       ← 4 credential verify tests
│   ├── test_beacon.py            ← 3 beacon receiver tests
│   ├── test_canary_generators.py ← 4 document generator & download tests
│   ├── test_contextual_evaluation.py ← 6 contextual scoring & threshold tests
│   ├── test_risk_scoring.py      ← 4 dynamic risk formula tests
│   ├── test_schemas.py           ← 12 Pydantic schema validation tests
│   ├── test_simulation.py        ← 4 end-to-end attack scenario tests
│   ├── test_stream.py            ← 2 SSE streaming & broadcast tests
│   ├── test_stress.py            ← 2 rate-limiter & concurrent stress tests
│   └── test_tokens.py            ← 5 token CRUD & filter tests
├── Aryan_Work.md                 ← Backend Lead & Architecture Work Log
├── Sana_Work.md                  ← This document
├── requirements.txt              ← Python dependency manifest
└── seed_test_data.py             ← Development database seeder
```

---

## How to Run & Verify

### 1. Run Automated Test Suite
```powershell
python -m pytest -v tests/
```
All **47 automated tests** execute and pass in under 5 seconds.

### 2. Launch the Application Server
```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

### 3. Open the Interactive Security Dashboard
Navigate to [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard) in any web browser to access:
- Real-time KPI Metric Cards (Active Decoys, Today's Triggers, Critical Threats).
- Token Management Table with real-time text search and status filtering.
- One-click token deployment modal with live criticality slider.
- Live Incident Monitor connected via Server-Sent Events (SSE).

### 4. Trigger Live Telemetry
Open a second terminal or browser tab and hit any deployed beacon:
```powershell
Invoke-WebRequest http://127.0.0.1:8000/beacon/<TOKEN_ID>
```
The Live Incident Stream on the dashboard immediately displays the newly triaged alert card in real time.

### 5. Interactive API Documentation (Swagger)
Explore and test all endpoints interactively at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).
