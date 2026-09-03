import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_scenario_1_single_recon_ping(client: AsyncClient):
    """
    Scenario 1: Insider finds a planted canary doc and opens it once during work hours.
    Expected: Low/Medium alert generated.
    """
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Internal Architecture Guide",
        "token_type": "canary_doc",
        "criticality": 20,
    })
    token_id = create_res.json()["data"]["token_id"]

    beacon_res = await client.get(
        f"/beacon/{token_id}",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Word/16.0",
            "X-Forwarded-For": "10.0.1.50",
        },
    )
    assert beacon_res.status_code == 200

    # Verify alert generated
    stats_res = await client.get("/api/v1/dashboard/stats")
    recent = stats_res.json()["data"]["recent_alerts"]
    matched = [a for a in recent if a["token_id"] == token_id]
    assert len(matched) == 1
    assert matched[0]["severity"] in ["Low", "Medium"]


@pytest.mark.asyncio
async def test_scenario_2_off_hours_document_snooping(client: AsyncClient):
    """
    Scenario 2: Insider accesses confidential compensation sheet using curl.
    Expected: High threat alert triggered due to tooling / off-hours modifier.
    """
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Q3 Executive Compensation Decoy",
        "token_type": "canary_doc",
        "criticality": 40,
    })
    token_id = create_res.json()["data"]["token_id"]

    beacon_res = await client.get(
        f"/beacon/{token_id}",
        headers={
            "User-Agent": "curl/8.4.0",
            "X-Forwarded-For": "198.51.100.22",
        },
    )
    assert beacon_res.status_code == 200

    stats_res = await client.get("/api/v1/dashboard/stats")
    recent = stats_res.json()["data"]["recent_alerts"]
    matched = [a for a in recent if a["token_id"] == token_id]
    assert len(matched) == 1
    # Criticality 40 * context (curl 1.2 or off-hours 1.5) >= 48
    assert matched[0]["severity"] in ["Medium", "High", "Critical"]


@pytest.mark.asyncio
async def test_scenario_3_rapid_credential_burst(client: AsyncClient):
    """
    Scenario 3: Automated brute-force or credential validation tool testing API key rapidly.
    Expected: Escalation to Critical severity alert due to frequency multiplier.
    """
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Production Stripe Secret Key",
        "token_type": "api_key",
        "criticality": 45,
    })
    token_id = create_res.json()["data"]["token_id"]

    # Fire 5 rapid verification requests
    for i in range(5):
        await client.post(
            "/api/v1/auth/verify",
            headers={
                "Authorization": f"Bearer {token_id}",
                "User-Agent": "python-requests/2.31.0",
                "X-Forwarded-For": "203.0.113.88",
            },
        )

    stats_res = await client.get("/api/v1/dashboard/stats")
    recent = stats_res.json()["data"]["recent_alerts"]
    matched = [a for a in recent if a["token_id"] == token_id]
    assert len(matched) >= 5

    # The latest alert should have escalated to Critical
    latest_alert = matched[0]
    assert latest_alert["severity"] == "Critical"
    assert latest_alert["risk_score"] >= 75.0


@pytest.mark.asyncio
async def test_scenario_4_revoked_token_probing(client: AsyncClient):
    """
    Scenario 4: Insider attempts to use an old, revoked honeytoken.
    Expected: Silently ignored, no trigger or alert logged.
    """
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Deprecated AWS Key",
        "token_type": "api_key",
        "criticality": 20,
    })
    token_id = create_res.json()["data"]["token_id"]
    await client.delete(f"/api/v1/tokens/{token_id}")

    stats_before = (await client.get("/api/v1/dashboard/stats")).json()["data"]

    # Probe revoked key via auth verify
    verify_res = await client.post(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {token_id}"},
    )
    assert verify_res.status_code == 401

    # Probe revoked key via beacon
    beacon_res = await client.get(f"/beacon/{token_id}")
    assert beacon_res.status_code == 200

    stats_after = (await client.get("/api/v1/dashboard/stats")).json()["data"]
    # Triggers and alerts must not increase
    assert stats_after["total_triggers"] == stats_before["total_triggers"]
    assert stats_after["total_alerts"] == stats_before["total_alerts"]
