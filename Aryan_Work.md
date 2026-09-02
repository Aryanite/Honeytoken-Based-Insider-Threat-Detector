# Aryan Singh — Work Log
**Role:** Backend Lead & Architecture  
**Team:** Honeytoken-Based Insider Threat Detector  
**Institution:** IILM University, Greater Noida — B.Tech CSE 2026–27  
**Supervisor:** Mr. Atul Kumar Singh

---

## Project Overview

Designed and implemented the core backend infrastructure for a deception-based insider threat detection system. The system plants fake digital assets (API keys, documents, database records) across the organization's infrastructure. When an internal actor accesses any of these decoy assets, the system silently captures their IP address, browser fingerprint, and timestamp, then feeds that data into a risk-scoring pipeline that generates severity-labeled alerts for the security administrator dashboard.

The backend is built on **Python + FastAPI** with **SQLAlchemy ORM** over **SQLite** (switchable to PostgreSQL via a single environment variable), and exposes a structured REST API used by all other team members to integrate their components.

---

## Git Repository Setup

- Initialized the Git repository and established the monorepo layout:
  ```
  /backend    ← FastAPI application (core, db, models, routes, schemas)
  /tests      ← Automated test suite (pytest + httpx)
  /decoys     ← Decoy artifact templates
  /docs       ← Architecture and API contracts
  ```
- Configured `.gitignore` to exclude Python caches (`__pycache__`, `*.pyc`), the local database file (`*.db`), secrets (`.env`), virtual environments (`.venv/`), and test artifacts.
- Committed `.env.example` as a safe template so teammates could configure their own local secrets without any real credentials entering version control.
- **Files:** [`.gitignore`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/.gitignore), [`.env.example`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/.env.example), [`requirements.txt`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/requirements.txt)

---

## Team-Wide API & Data Contract

Authored [`docs/contract.md`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/docs/contract.md) — the foundational agreement that allows all four team members to build their components independently without blocking on each other's code.

The contract defines:

**Field contracts for all three ORM entities:**

| Entity | Key Fields |
|---|---|
| `HoneyToken` | `token_id` (UUID), `name`, `token_type` (`api_key`/`canary_doc`/`db_record`), `criticality` (1–50), `status` (`active`/`revoked`) |
| `TokenTrigger` | `trigger_id`, `token_id` (FK), `source_ip`, `user_agent`, `headers` (JSON), `triggered_at` |
| `AlertLog` | `alert_id`, `trigger_id` (FK), `severity` (`Low`/`Medium`/`High`/`Critical`), `risk_score`, `details` (JSON) |

**Standardized JSON response envelope (all `/api/v1/*` endpoints):**
```json
{
  "status": "success | error",
  "data": { ... } | null,
  "error": "message" | null
}
```

**Route prefix rules:**
- `/api/v1` — all protected administrative endpoints
- `/beacon` — public telemetry listener (intentionally unauthenticated)

---

## Application Configuration

Implemented [`backend/core/config.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/core/config.py) using **Pydantic Settings** (`BaseSettings`) which automatically resolves configuration from environment variables and the `.env` file at startup.

Key settings exposed:

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./honeytoken.db` | Primary database connection string |
| `BEACON_BASE_URL` | `http://127.0.0.1:8000` | Used to construct canary tracking URLs |
| `API_V1_STR` | `/api/v1` | API route prefix |
| `BACKEND_CORS_ORIGINS` | localhost:3000/8000 | Allowed CORS origins for frontend |
| `SECRET_KEY` | dev placeholder | Signing key (replaced in production) |

Swapping from SQLite to PostgreSQL in any environment requires only changing `DATABASE_URL` — no code modifications needed.

---

## Database Layer

### Engine & Session Management
Implemented [`backend/db/session.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/db/session.py):
- Creates a SQLAlchemy `engine` from `DATABASE_URL`, applying `check_same_thread: False` automatically when SQLite is detected (required for FastAPI's multi-threaded request handling).
- Provides a `get_db()` generator function used as a FastAPI dependency that opens a session at the start of each request and guarantees closure in a `finally` block — preventing connection leaks.

### Declarative Base
Implemented [`backend/db/base.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/db/base.py): the shared `Base = declarative_base()` instance from which all ORM models inherit to register with SQLAlchemy's metadata system.

---

## SQLAlchemy ORM Models

### HoneyToken — [`backend/models/token.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/models/token.py)
The central data model representing each deployed decoy asset.

- `token_id`: UUIDv4 string primary key, auto-generated via `lambda: str(uuid.uuid4())`.
- `token_type`: constrained to `api_key`, `canary_doc`, or `db_record` at the schema validation layer.
- `criticality`: integer `1–50` representing asset sensitivity — the foundational weight in the Week 3 scoring formula.
- `status`: `active` (triggers logged) or `revoked` (beacon silently ignored).
- `created_at` / `updated_at`: timezone-aware UTC timestamps using `datetime.now(timezone.utc)`.
- Cascade relationship to `TokenTrigger` — deleting a honeytoken automatically purges all its trigger records.

### TokenTrigger — [`backend/models/trigger.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/models/trigger.py)
Records every access event against a honeytoken beacon.

- `source_ip`: up to 45 characters to support both IPv4 and IPv6 addresses.
- `headers`: stored as a JSON column — preserves full HTTP request context for forensic analysis.
- `triggered_at`: indexed for fast time-window queries (used in Week 3 burst frequency calculations).
- Cascade relationship to `AlertLog` — trigger deletion cascades to alert records.

### AlertLog — [`backend/models/alert.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/models/alert.py)
Stores triage output from the risk-scoring engine (implemented in Week 3).

- `severity`: one of `Low`, `Medium`, `High`, `Critical`.
- `risk_score`: float representing the computed danger level.
- `details`: JSON column containing the score breakdown (asset weight, frequency multiplier, time-of-access modifier) for analyst review.
- `created_at`: indexed for dashboard timeline queries.

---

## Pydantic Validation Schemas

Implemented the request/response schema layer in [`backend/schemas/`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/schemas/).

### Standard Envelope — [`backend/schemas/envelope.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/schemas/envelope.py)
Generic `ApiResponse[T]` class using Pydantic's `Generic[T]` so the `data` field is typed to the specific response object for each endpoint. Includes `success_response()` and `error_response()` factory helpers that all routes use to guarantee contract compliance.

### Token Schemas — [`backend/schemas/token.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/schemas/token.py)

| Schema | Purpose |
|---|---|
| `TokenCreateSchema` | Validates `POST /api/v1/tokens` input — enforces `token_type` literal, `criticality` range 1–50 |
| `TokenUpdateSchema` | Partial update schema using `exclude_unset=True` so only provided fields are written |
| `TokenResponseSchema` | Serializes ORM models to JSON — includes a computed `beacon_url` field |

`build_beacon_url(token_id)` is a standalone pure helper that constructs the full public beacon URL from `BEACON_BASE_URL` + `/beacon/` + the token UUID. This function is also imported by the seed script so developers always see the correct tracking link when seeding test data.

`TokenResponseSchema.from_orm_model()` is a class factory method that safely maps the SQLAlchemy ORM object to the Pydantic response schema, injects the beacon URL, and limits recent triggers to the 10 most recent entries to keep API responses lean.

---

## FastAPI REST Endpoints

Implemented in [`backend/routes/tokens.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/routes/tokens.py) under the `/api/v1/tokens` prefix.

| Method | Route | Description |
|---|---|---|
| `POST` | `/api/v1/tokens` | Create and register a new honeytoken. Returns `201 Created` with full token details and beacon URL |
| `GET` | `/api/v1/tokens` | List all honeytokens. Supports `?status=active\|revoked` and `?token_type=api_key\|canary_doc\|db_record` query filters |
| `GET` | `/api/v1/tokens/{token_id}` | Retrieve a single token's details including its 10 most recent trigger events |
| `PATCH` | `/api/v1/tokens/{token_id}` | Update a token's name, criticality, status, or placement location |
| `DELETE` | `/api/v1/tokens/{token_id}` | Soft-revoke a token — changes `status` to `revoked`, no data is deleted |

All endpoints return the standard `ApiResponse[T]` envelope. `404 Not Found` and `422 Unprocessable Entity` errors are captured by global exception handlers in `main.py` and also formatted as the standard envelope so the frontend always receives a consistent shape.

The `?status=` query parameter is aliased internally to `token_status` to avoid shadowing FastAPI's own `status` module import.

---

## Telemetry Beacon Listener

Implemented in [`backend/routes/beacon.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/routes/beacon.py).

**Route:** `GET /beacon/{token_id}`

This is the core covert capture mechanism. When a decoy asset is accessed by a potential insider — for example, if a canary `.env` file is opened and its contents are used, or a canary Word document is opened in Microsoft Word — the embedded beacon URL fires an HTTP GET request to this endpoint.

**Design decisions:**
- **Always unauthenticated:** No authentication headers are required or checked. A real attacker would never voluntarily add credentials to their request, and requiring auth would cause the beacon to fail silently without logging anything.
- **Always returns 200 with a 1x1 transparent GIF:** The response is a 43-byte standard GIF image (`image/gif`) regardless of whether the token exists, is revoked, or is active. This ensures the accessor sees no error that could tip them off that they triggered a security mechanism.
- **IP resolution with proxy support:** The `_extract_client_telemetry()` function reads `X-Forwarded-For` first to handle reverse-proxy environments where the direct socket IP would be the proxy, not the actual user. The leftmost entry in XFF is taken as the originating client IP.
- **Anti-caching headers:** `Cache-Control: no-cache, no-store, must-revalidate` ensures that even if the canary document is re-opened, every access fires a fresh HTTP request and is independently logged rather than served from cache.
- **Selective logging:** Only `active` honeytokens generate trigger records. Revoked or unknown token IDs return the same GIF silently — this prevents an attacker who discovers the token ID from flooding the alert log by hitting a revoked token repeatedly.

---

## FastAPI Application Entry Point

Implemented [`backend/main.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/backend/main.py):

- Uses FastAPI's `lifespan` async context manager to call `Base.metadata.create_all()` on application startup — tables are auto-created the first time the server runs.
- **CORS middleware** configured from `BACKEND_CORS_ORIGINS` so the React frontend can query the API from a different port without browser-level cross-origin blocks.
- **Global exception handlers:**
  - `StarletteHTTPException` → formats `404`, `405` etc. into the standard `{status, data, error}` envelope.
  - `RequestValidationError` → formats Pydantic `422` validation failures (e.g. invalid `token_type`, out-of-range `criticality`) into the same envelope with a readable error message listing the failing field and constraint.
- Exposes `GET /health` for uptime monitoring and readiness probing.
- Swagger interactive docs at `/docs`, ReDoc at `/redoc` (auto-generated from route definitions and Pydantic schemas).

---

## Test Seeder Script

Implemented [`seed_test_data.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/seed_test_data.py) as a standalone CLI script that pre-populates the development database with representative honeytokens covering all three types and both statuses:

| Token Name | Type | Criticality | Status |
|---|---|---|---|
| AWS Production S3 Read Access Key | `api_key` | 45 | active |
| Q3 Executive Compensation & Bonus Plan | `canary_doc` | 40 | active |
| Payroll Admin Database Honeytoken Record | `db_record` | 50 | active |
| Deprecated Stripe Integration Secret | `api_key` | 15 | revoked |

The script is idempotent — re-running it skips tokens that already exist by name, so it can safely be run multiple times without creating duplicates.

---

## Automated Test Suite (Backend Foundations)

Set up the testing infrastructure in [`tests/`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/tests/):

### Test Harness — [`tests/conftest.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/tests/conftest.py)
- `db_session` fixture: creates a fully isolated in-memory SQLite database for each test function using `StaticPool` to avoid cross-connection state. Tables are created before the test and dropped after — guaranteeing test isolation.
- `client` fixture: provides an `httpx.AsyncClient` pointing at the FastAPI app via `ASGITransport` (no actual network socket). The `get_db` dependency is overridden with the test session so all requests hit the in-memory DB, never the development database file.

### Token CRUD Tests — [`tests/test_tokens.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/tests/test_tokens.py)

| Test | What it verifies |
|---|---|
| `test_create_honeytoken_success` | Token creation returns `201`, correct fields, and a valid beacon URL containing the token ID |
| `test_create_honeytoken_invalid_criticality` | `criticality: 99` returns `422` with error message referencing the `criticality` field |
| `test_create_honeytoken_invalid_type` | Unknown `token_type` returns `422` with error referencing `token_type` |
| `test_list_and_filter_tokens` | Listing with `?status=active` and `?status=revoked` filters correctly isolates tokens |
| `test_get_single_token` | Single token fetch returns correct data; non-existent UUID returns `404` in the standard envelope |

### Beacon Listener Tests — [`tests/test_beacon.py`](file:///d:/Honeytoken-Based-Insider-Threat-Detector/tests/test_beacon.py)

| Test | What it verifies |
|---|---|
| `test_beacon_trigger_active_token` | Hitting an active token's beacon returns `image/gif`, starts with `GIF89a`, and creates a `TokenTrigger` record with the correct IP extracted from `X-Forwarded-For` |
| `test_beacon_revoked_token_silent` | Hitting a revoked token returns `image/gif` but logs **no trigger** — no false alerts |
| `test_beacon_non_existent_token_silent` | Non-existent UUID returns `image/gif` without crashing — attacker learns nothing |

**All 8 automated tests pass:**
```
8 passed in 0.52s
```

---

## Repository Snapshot

```
d:/Honeytoken-Based-Insider-Threat-Detector/
├── backend/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py          ← Pydantic Settings configuration
│   ├── db/
│   │   ├── __init__.py
│   │   ├── base.py            ← SQLAlchemy Declarative Base
│   │   └── session.py         ← Engine, sessionmaker, get_db dependency
│   ├── models/
│   │   ├── __init__.py
│   │   ├── token.py           ← HoneyToken ORM model
│   │   ├── trigger.py         ← TokenTrigger ORM model
│   │   └── alert.py           ← AlertLog ORM model
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── tokens.py          ← Token CRUD endpoints (/api/v1/tokens)
│   │   └── beacon.py          ← Telemetry beacon listener (/beacon/{id})
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── envelope.py        ← ApiResponse[T] standard envelope
│   │   ├── token.py           ← Token create/update/response schemas
│   │   └── trigger.py         ← Trigger response schema
│   └── main.py                ← FastAPI app, CORS, exception handlers
├── decoys/
│   ├── sample_credentials.env ← Decoy AWS/Stripe credential template
│   └── sample_config.yaml     ← Decoy cloud service config template
├── docs/
│   └── contract.md            ← Team API & data model contract
├── tests/
│   ├── __init__.py
│   ├── conftest.py            ← Fixtures: in-memory DB, async test client
│   ├── test_tokens.py         ← 5 CRUD and validation tests
│   └── test_beacon.py         ← 3 beacon telemetry tests
├── .env                       ← Local secrets (gitignored)
├── .env.example               ← Environment variables template
├── .gitignore
├── Plan.md                    ← 5-week project implementation plan
├── pytest.ini                 ← Test runner configuration
├── README.md                  ← Project onboarding and documentation
├── requirements.txt           ← Python dependency manifest
└── seed_test_data.py          ← Development database seeder
```

---

## How to Run

**Start the server:**
```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

**Seed development data:**
```powershell
python seed_test_data.py
```

**Run automated tests:**
```powershell
python -m pytest -v tests/
```

**Trigger a beacon manually (PowerShell):**
```powershell
Invoke-WebRequest http://127.0.0.1:8000/beacon/<TOKEN_ID>
```

**Explore the API interactively:**  
Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) in a browser.
