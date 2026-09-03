import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_auth_verify_active_api_key_creates_trigger_and_alert(client: AsyncClient):
    # 1. Create active API key token
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Stripe Live Secret Decoy Key",
        "token_type": "api_key",
        "criticality": 45,
    })
    token_id = create_res.json()["data"]["token_id"]

    # 2. Rogue actor probes the API key using Authorization Bearer header
    headers = {
        "Authorization": f"Bearer {token_id}",
        "User-Agent": "curl/8.4.0",
        "X-Forwarded-For": "198.51.100.99",
    }
    verify_res = await client.post("/api/v1/auth/verify", headers=headers)
    assert verify_res.status_code == 401
    assert "WWW-Authenticate" in verify_res.headers
    assert verify_res.json()["error"] is not None

    # 3. Verify that a trigger was logged
    token_res = await client.get(f"/api/v1/tokens/{token_id}")
    triggers = token_res.json()["data"]["recent_triggers"]
    assert len(triggers) == 1
    assert triggers[0]["source_ip"] == "198.51.100.99"
    assert "curl" in triggers[0]["user_agent"]

    # 4. Verify dashboard stats reflect the trigger and created alert
    stats_res = await client.get("/api/v1/dashboard/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()["data"]
    assert stats["total_triggers"] >= 1
    assert stats["total_alerts"] >= 1
    assert len(stats["recent_alerts"]) >= 1


@pytest.mark.asyncio
async def test_auth_verify_json_payload(client: AsyncClient):
    # 1. Create active API key token
    create_res = await client.post("/api/v1/tokens", json={
        "name": "AWS Production Read Key",
        "token_type": "api_key",
        "criticality": 30,
    })
    token_id = create_res.json()["data"]["token_id"]

    # 2. Probe with JSON body
    verify_res = await client.post(
        "/api/v1/auth/verify",
        json={"api_key": token_id},
        headers={"X-Forwarded-For": "203.0.113.15"},
    )
    assert verify_res.status_code == 401

    # 3. Verify trigger logged
    token_res = await client.get(f"/api/v1/tokens/{token_id}")
    assert len(token_res.json()["data"]["recent_triggers"]) == 1


@pytest.mark.asyncio
async def test_auth_verify_revoked_key_silent(client: AsyncClient):
    # 1. Create and revoke token
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Revoked Key Decoy",
        "token_type": "api_key",
        "criticality": 10,
    })
    token_id = create_res.json()["data"]["token_id"]
    await client.delete(f"/api/v1/tokens/{token_id}")

    # 2. Probe revoked key
    verify_res = await client.post(
        "/api/v1/auth/verify",
        json={"api_key": token_id},
    )
    assert verify_res.status_code == 401

    # 3. Verify NO trigger logged
    token_res = await client.get(f"/api/v1/tokens/{token_id}")
    assert len(token_res.json()["data"]["recent_triggers"]) == 0


@pytest.mark.asyncio
async def test_auth_verify_missing_credential_returns_400(client: AsyncClient):
    verify_res = await client.post("/api/v1/auth/verify")
    assert verify_res.status_code == 400
