"""
CyberGuard SOC Comprehensive Automated Test Suite
Validates mathematical risk scoring, decoy generation, beacon trapping,
auth honeypot gateway, active quarantine, and zero-legacy branding.
"""

import os
import glob
import pytest
from datetime import datetime

from app.app import app, load_tokens, save_tokens
from alerts.risk_scoring import calculate_risk_score, classify_severity
from database.database import (
    create_database,
    save_event,
    get_all_events,
    block_ip,
    unblock_ip,
    is_ip_blocked,
)
from honeytokens.file_honeytoken import (
    generate_file_honeytoken,
    DECOY_FOLDER,
)


@pytest.fixture
def client():
    app.config["TESTING"] = True
    create_database()
    with app.test_client() as client:
        yield client


# ============================================================================
# 1. Dynamic Risk Scoring Engine Tests
# ============================================================================

def test_risk_scoring_business_hours_vs_off_hours():
    """Verify context multiplier jumps from 1.0x (business) to 1.5x (off-hours)."""
    # Mon at 11:00 AM (business)
    dt_business = datetime(2026, 10, 26, 11, 0, 0)
    res_biz = calculate_risk_score("employee_handbook.docx", "Mozilla/5.0", access_time=dt_business)
    assert res_biz["asset_weight"] == 30.0
    assert res_biz["context_multiplier"] == 1.0
    assert res_biz["risk_score"] == 30.0
    assert res_biz["severity"] == "Medium"

    # Mon at 11:00 PM (off-hours)
    dt_off = datetime(2026, 10, 26, 23, 0, 0)
    res_off = calculate_risk_score("employee_handbook.docx", "Mozilla/5.0", access_time=dt_off)
    assert res_off["context_multiplier"] == 1.5
    assert res_off["risk_score"] == 45.0
    assert res_off["severity"] == "Medium"


def test_risk_scoring_cli_multiplier():
    """Verify automated CLI / pentest tools apply 1.2x multiplier."""
    dt_biz = datetime(2026, 10, 26, 11, 0, 0)
    res_curl = calculate_risk_score("aws_prod.env", "curl/8.4.0", access_time=dt_biz)
    assert res_curl["asset_weight"] == 45.0
    # 1.0 (biz) * 1.2 (cli) = 1.2
    assert res_curl["context_multiplier"] == 1.2
    assert res_curl["risk_score"] == 54.0
    assert res_curl["severity"] == "High"


def test_risk_scoring_burst_frequency():
    """Verify frequency multipliers: 1 hit (1.0x), 2-4 hits (1.3x), >=5 hits (1.8x)."""
    r1 = calculate_risk_score("config.yaml", "curl/8.4.0", recent_hits=1, force_off_hours=True)
    r3 = calculate_risk_score("config.yaml", "curl/8.4.0", recent_hits=3, force_off_hours=True)
    r5 = calculate_risk_score("config.yaml", "curl/8.4.0", recent_hits=5, force_off_hours=True)

    assert r1["frequency_multiplier"] == 1.0
    assert r3["frequency_multiplier"] == 1.3
    assert r5["frequency_multiplier"] == 1.8

    # r5: 45.0 * 1.8 * 1.8 = 145.8 -> Critical
    assert r5["risk_score"] == 145.8
    assert r5["severity"] == "Critical"


def test_severity_thresholds():
    """Verify severity tier boundaries."""
    assert classify_severity(10.0) == "Low"
    assert classify_severity(25.0) == "Low"
    assert classify_severity(25.1) == "Medium"
    assert classify_severity(50.0) == "Medium"
    assert classify_severity(50.1) == "High"
    assert classify_severity(75.0) == "High"
    assert classify_severity(75.1) == "Critical"
    assert classify_severity(120.0) == "Critical"


# ============================================================================
# 2. Native Multi-Format Decoy Generation Tests
# ============================================================================

def test_native_pdf_generation():
    """Verify native binary PDF starts with %PDF-1.4 and embeds /OpenAction URI."""
    token = generate_file_honeytoken("Executive_Payroll_Test.pdf")
    file_path = os.path.join(DECOY_FOLDER, token["filename"])
    assert os.path.exists(file_path)

    with open(file_path, "rb") as f:
        data = f.read()

    assert data.startswith(b"%PDF-1.4"), "PDF must begin with valid %PDF-1.4 header"
    assert b"/OpenAction" in data, "PDF must include embedded /OpenAction beacon trigger"
    assert b"/URI" in data, "PDF must include /URI action"
    assert b"%%EOF" in data, "PDF must include proper trailer ending"


def test_env_credential_decoy_generation():
    """Verify .env generation contains realistic high-entropy keys and endpoints."""
    token = generate_file_honeytoken("aws_prod_credentials.env")
    file_path = os.path.join(DECOY_FOLDER, token["filename"])
    assert os.path.exists(file_path)

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "AKIA" in content, "Decoy must synthesize realistic AWS key beginning with AKIA"
    assert "sk_live_" in content, "Decoy must synthesize realistic Stripe key starting with sk_live_"
    assert "INTERNAL_AUTH_VERIFY_ENDPOINT" in content
    assert "BEACON_HEALTH_URI" in content


# ============================================================================
# 3. Beacon & Honeypot Listener Tests
# ============================================================================

def test_beacon_endpoint_returns_43_byte_gif(client):
    """Verify GET /beacon/<token_id> returns HTTP 200, image/gif, 43 bytes, and cache-control."""
    token = generate_file_honeytoken("Sensitive_Compensation.pdf")
    resp = client.get(f"/beacon/{token['token_id']}")

    assert resp.status_code == 200
    assert resp.mimetype == "image/gif"
    assert len(resp.data) == 43
    assert "no-store" in resp.headers.get("Cache-Control", "")


def test_auth_verify_honeypot_gateway(client):
    """Verify POST /api/v1/auth/verify traps probe with 401 and WWW-Authenticate."""
    resp = client.post(
        "/api/v1/auth/verify",
        json={"token": "sk_live_test_unauthorized_probe"},
        headers={"Authorization": "Bearer sk_live_test_unauthorized_probe", "User-Agent": "curl/8.4.0"},
    )

    assert resp.status_code == 401
    assert "invalid_token" in resp.headers.get("WWW-Authenticate", "")
    data = resp.get_json()
    assert data["status"] == "error"
    assert "invalid" in data["error"].lower()


def test_revoked_token_suppresses_alerts(client):
    """Verify hitting a revoked token returns GIF without generating false-positive incidents."""
    token = generate_file_honeytoken("Decommissioned_Plan.pdf")
    token_id = token["token_id"]

    # Revoke the token
    tokens = load_tokens()
    for t in tokens:
        if t.get("token_id") == token_id:
            t["status"] = "REVOKED"
    save_tokens(tokens)

    events_before = len(get_all_events())
    resp = client.get(f"/beacon/{token_id}")
    assert resp.status_code == 200
    assert resp.mimetype == "image/gif"
    events_after = len(get_all_events())

    assert events_after == events_before, "Access to a REVOKED token must not log false-positive alerts."


def test_active_ip_blocking(client):
    """Verify blocking an IP results in HTTP 403 on subsequent requests."""
    test_ip = "198.51.100.77"
    block_ip(test_ip, datetime.now().isoformat())
    assert is_ip_blocked(test_ip) is True

    token = generate_file_honeytoken("Quarantine_Test.pdf")
    resp = client.get(
        f"/beacon/{token['token_id']}",
        headers={"X-Forwarded-For": test_ip},
    )
    assert resp.status_code == 403

    unblock_ip(test_ip)
    assert is_ip_blocked(test_ip) is False


# ============================================================================
# 4. Zero Legacy Branding Check
# ============================================================================

def test_zero_legacy_branding():
    """Verify legacy prototype branding does not appear in any HTML template or README.md."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = os.path.join(base_dir, "templates")
    readme_file = os.path.join(base_dir, "README.md")
    legacy_name = "canary" + "shield"
    legacy_repo = "canary-token" + "-honey-token"

    html_files = glob.glob(os.path.join(templates_dir, "*.html"))
    for file_path in html_files:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().lower()
            assert legacy_name not in content, f"Found legacy branding in {file_path}"
            assert legacy_repo not in content, f"Found legacy repo name in {file_path}"

    if os.path.exists(readme_file):
        with open(readme_file, "r", encoding="utf-8") as f:
            content = f.read().lower()
            assert legacy_name not in content, "Found legacy branding in README.md"
