import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_beacon_trigger_active_token(client: AsyncClient):
    # 1. Create active token
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Beacon Active Test Token",
        "token_type": "canary_doc",
        "criticality": 40,
    })
    token_id = create_res.json()["data"]["token_id"]

    # 2. Trigger beacon
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CanaryTest/1.0",
        "X-Forwarded-For": "198.51.100.42, 10.0.0.1",
    }
    beacon_res = await client.get(f"/beacon/{token_id}", headers=headers)
    assert beacon_res.status_code == 200
    assert beacon_res.headers["content-type"] == "image/gif"
    assert beacon_res.content.startswith(b"GIF89a")
    assert len(beacon_res.content) in (42, 43)

    # 3. Verify trigger record was logged
    token_res = await client.get(f"/api/v1/tokens/{token_id}")
    token_data = token_res.json()["data"]
    triggers = token_data["recent_triggers"]
    assert len(triggers) == 1
    assert triggers[0]["source_ip"] == "198.51.100.42"
    assert "CanaryTest" in triggers[0]["user_agent"]


@pytest.mark.asyncio
async def test_beacon_revoked_token_silent(client: AsyncClient):
    # 1. Create and revoke token
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Beacon Revoked Test Token",
        "token_type": "api_key",
        "criticality": 20,
    })
    token_id = create_res.json()["data"]["token_id"]
    await client.delete(f"/api/v1/tokens/{token_id}")

    # 2. Trigger beacon on revoked token
    beacon_res = await client.get(f"/beacon/{token_id}")
    assert beacon_res.status_code == 200
    assert beacon_res.headers["content-type"] == "image/gif"

    # 3. Verify no trigger logged
    token_res = await client.get(f"/api/v1/tokens/{token_id}")
    assert len(token_res.json()["data"]["recent_triggers"]) == 0


@pytest.mark.asyncio
async def test_beacon_non_existent_token_silent(client: AsyncClient):
    # Trigger beacon with random UUID
    beacon_res = await client.get("/beacon/00000000-0000-0000-0000-000000000000")
    assert beacon_res.status_code == 200
    assert beacon_res.headers["content-type"] == "image/gif"
    assert beacon_res.content.startswith(b"GIF89a")
