# Saumya Kashyap — Work Log
**Role:** Decoy Artifact Templates, Ethical Framing & Active Containment UI  
**Team:** Honeytoken-Based Insider Threat Detector  
**Institution:** IILM University, Greater Noida — B.Tech CSE 2026–27  
**Supervisor:** Mr. Atul Kumar Singh  

---

## Project Overview

In this project, traditional perimeter cybersecurity mechanisms fail against malicious internal actors operating with legitimate access privileges. Our system deploys an enterprise-grade deception grid: multi-format honeytokens (synthetic cloud API keys, canary Word/PDF documents, and decoy database records) are planted across internal developer workspaces, `.env` files, and shared cloud folders.

When an internal actor accesses or probes any of these decoy assets, covert telemetry listeners silently record the actor's IP address, browser/client fingerprint, and timestamp without tipping them off. This telemetry feeds into a **Dynamic Risk-Scoring Engine** ($W \times C \times F$) that computes a threat score and pushes sub-millisecond alerts over Server-Sent Events (SSE) to the security administrator dashboard.

As the **Decoy Artifact Templates, Ethical Framing & Active Containment UI Lead**, my core responsibilities span:

1. **Decoy Configuration & Credential Templates (`/decoys/`):** Designing realistic corporate deception templates (`sample_config.yaml`, `sample_credentials.env`) simulating high-value production environments to entice unauthorized internal reconnaissance.
2. **High-Entropy Key Generation Utilities:** Establishing the realistic pretexting formats for synthetic AWS access keys (`AKIA...`), Stripe live secrets (`sk_live_...`), and corporate PostgreSQL connection strings.
3. **Active Containment & Quarantine Interface (`templates/dashboard.html` & `static/style.css`):** Building the front-end user experience for one-click workstation quarantine (`/api/block-ip`), host release (`/api/unblock-ip`), and token decommissioning (`/api/revoke-token`).
4. **Ethical Deception Framing & Legal Policy:** Drafting the ethical framework ensuring that deception assets remain strictly passive, do not alter employee workstations, prevent entrapment, and comply with corporate privacy guidelines.
5. **SOC Incident Monitor UX & Triage Badges:** Styling the color-coded severity badges (Critical, High, Medium, Low) and quick-preset deployment buttons (`Executive_Payroll_2026.pdf`, `M&A_Board_Strategy.docx`, `aws_prod_credentials.env`).

---

## Decoy Artifact Templates & Pretexting

Implemented in [`decoys/sample_config.yaml`](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/decoys/sample_config.yaml) and [`decoys/sample_credentials.env`](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/decoys/sample_credentials.env).

### Realistic Corporate Decoy Assets

To be effective, honeytokens must appear completely authentic to an insider who is browsing internal file shares or source code repositories:

1. **Production Cloud Environment Secrets (`.env`):**
   - Synthesizes realistic 20-character AWS access keys prefixed with `AKIA` and 40-character base64 secrets.
   - Includes realistic live Stripe payment gateway secrets prefixed with `sk_live_`.
   - Embeds the covert health check and verification endpoints pointing to the honeypot auth gateway (`/api/v1/auth/verify`).

2. **Enterprise Service Configuration (`.yaml`):**
   - Simulates internal microservice configuration files (`employee-benefits-sync`) with fake PostgreSQL database credentials (`db-internal-prod.corporate.local`).
   - Embeds covert heartbeat URLs linking to the telemetry beacon route (`/beacon/<token_id>`).

3. **Restricted Executive Documents (`.pdf` / `.docx`):**
   - Formatted as board compensation matrices, financial payroll reports, and M&A strategy plans.
   - Embeds hidden `/OpenAction` URIs (PDF) and OpenXML web blips (DOCX) that trigger the 43-byte transparent GIF beacon silently upon opening.

---

## Active Containment & Quarantine UI

Implemented in [`templates/dashboard.html`](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/templates/dashboard.html).

### 1. One-Click Host Quarantine
- When a threat actor triggers a honeytoken, an immediate **"Quarantine IP"** button appears on the incident row.
- Clicking the button sends a `POST /api/block-ip` request containing the source IP address.
- The server registers the IP in the SQLite `blocked_ips` table, and all subsequent access attempts from that workstation receive an immediate **HTTP 403 Forbidden**.
- The UI dynamically switches the button to a bright red `QUARANTINED` badge.

### 2. Workstation Quarantine Registry Table
- Displays all currently isolated IP addresses along with the exact isolation timestamp.
- Provides a **"Release Quarantine"** button (`POST /api/unblock-ip`) allowing security analysts to restore host connectivity once an incident is resolved.

### 3. Lifecycle Token Revocation
- When a decoy file is decommissioned or leaked outside testing, analysts can click **"Revoke Trap"** (`POST /api/revoke-token`).
- Revoked tokens transition to `REVOKED` status in `tokens.json`.
- Subsequent access attempts receive the transparent GIF silently without raising false-positive alarms on the dashboard.

---

## Ethical Framing & Legal Safeguards

Insider threat detection through deception must adhere to strict ethical and legal boundaries:

1. **Entrapment Avoidance:** Deception assets are strictly passive tripwires placed in restricted directories where employees have no legitimate business purpose to look. No employees are coerced or prompted to access these files.
2. **Workplace Privacy Protection:** The system collects strictly technical access telemetry (`X-Forwarded-For` IP address, HTTP User-Agent, and access timestamp). It does not perform invasive endpoint keystroke logging or screen capture.
3. **Transparent Policy Alignment:** Organization acceptable-use policies explicitly state that corporate workstations and shared drives are subject to automated security auditing and intrusion monitoring.

---

## Verification & Impact

- **Quarantine Response Latency:** Host isolation takes effect in **< 10 milliseconds** via in-memory set lookups and SQLite persistence.
- **Containment Reliability:** Verified via [`tests/test_cyberguard.py::test_active_ip_blocking`](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/tests/test_cyberguard.py#L181-L197) — blocked hosts consistently receive HTTP 403 Forbidden on both beacon and API routes.
- **Zero False-Positive Revocation:** Verified via [`tests/test_cyberguard.py::test_revoked_token_suppresses_alerts`](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/tests/test_cyberguard.py#L160-L180).
