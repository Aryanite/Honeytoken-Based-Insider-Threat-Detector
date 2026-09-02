import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_honeytoken_success(client: AsyncClient):
    payload = {
        "name": "Test AWS Decoy Key",
        "token_type": "api_key",
        "criticality": 35,
        "description": "Planted in git repo for test",
        "placement_location": "repo://.env",
    }
    response = await client.post("/api/v1/tokens", json=payload)
    assert response.status_code == 201
    res_json = response.json()
    assert res_json["status"] == "success"
    assert res_json["error"] is None

    data = res_json["data"]
    assert data["name"] == payload["name"]
    assert data["token_type"] == "api_key"
    assert data["criticality"] == 35
    assert data["status"] == "active"
    assert "beacon_url" in data
    assert data["token_id"] in data["beacon_url"]


@pytest.mark.asyncio
async def test_create_honeytoken_invalid_criticality(client: AsyncClient):
    # Criticality must be 1 to 50
    payload = {
        "name": "Invalid Criticality Token",
        "token_type": "api_key",
        "criticality": 99,
    }
    response = await client.post("/api/v1/tokens", json=payload)
    assert response.status_code == 422
    res_json = response.json()
    assert res_json["status"] == "error"
    assert "criticality" in res_json["error"]


@pytest.mark.asyncio
async def test_create_honeytoken_invalid_type(client: AsyncClient):
    # Invalid token_type
    payload = {
        "name": "Invalid Type Token",
        "token_type": "ssh_key_unknown",
        "criticality": 20,
    }
    response = await client.post("/api/v1/tokens", json=payload)
    assert response.status_code == 422
    res_json = response.json()
    assert res_json["status"] == "error"
    assert "token_type" in res_json["error"]


@pytest.mark.asyncio
async def test_list_and_filter_tokens(client: AsyncClient):
    # 1. Create active token
    t1 = await client.post("/api/v1/tokens", json={
        "name": "Active Canary Doc",
        "token_type": "canary_doc",
        "criticality": 30,
    })
    # 2. Create another active token
    t2 = await client.post("/api/v1/tokens", json={
        "name": "Active DB Record",
        "token_type": "db_record",
        "criticality": 45,
    })
    t2_id = t2.json()["data"]["token_id"]

    # 3. Revoke second token
    await client.delete(f"/api/v1/tokens/{t2_id}")

    # 4. List all
    all_res = await client.get("/api/v1/tokens")
    assert all_res.status_code == 200
    assert len(all_res.json()["data"]) == 2

    # 5. Filter active only
    active_res = await client.get("/api/v1/tokens?status=active")
    assert active_res.status_code == 200
    active_data = active_res.json()["data"]
    assert len(active_data) == 1
    assert active_data[0]["name"] == "Active Canary Doc"

    # 6. Filter revoked only
    revoked_res = await client.get("/api/v1/tokens?status=revoked")
    assert revoked_res.status_code == 200
    revoked_data = revoked_res.json()["data"]
    assert len(revoked_data) == 1
    assert revoked_data[0]["token_id"] == t2_id


@pytest.mark.asyncio
async def test_get_single_token(client: AsyncClient):
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Single Token Test",
        "token_type": "api_key",
        "criticality": 25,
    })
    token_id = create_res.json()["data"]["token_id"]

    get_res = await client.get(f"/api/v1/tokens/{token_id}")
    assert get_res.status_code == 200
    assert get_res.json()["data"]["token_id"] == token_id

    # 404 test
    not_found = await client.get("/api/v1/tokens/non-existent-uuid")
    assert not_found.status_code == 404
    assert not_found.json()["status"] == "error"
