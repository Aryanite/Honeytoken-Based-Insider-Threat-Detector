import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_and_get_alerts_endpoints(client: AsyncClient):
    # 1. Create active token
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Alert Query Canary",
        "token_type": "api_key",
        "criticality": 40,
    })
    token_id = create_res.json()["data"]["token_id"]

    # 2. Trigger beacon to generate an alert
    await client.get(f"/beacon/{token_id}", headers={"User-Agent": "curl/7.88.1"})

    # 3. Query all alerts via /api/v1/alerts
    alerts_res = await client.get("/api/v1/alerts")
    assert alerts_res.status_code == 200
    alerts_envelope = alerts_res.json()
    assert alerts_envelope["status"] == "success"
    alerts = alerts_envelope["data"]
    assert len(alerts) >= 1

    first_alert = alerts[0]
    alert_id = first_alert["alert_id"]
    assert first_alert["severity"] in ["Low", "Medium", "High", "Critical"]
    assert first_alert["risk_score"] > 0

    # 4. Query single alert details
    detail_res = await client.get(f"/api/v1/alerts/{alert_id}")
    assert detail_res.status_code == 200
    detail_data = detail_res.json()["data"]
    assert detail_data["alert_id"] == alert_id
    assert "asset_weight" in detail_data["details"]

    # 5. Filter by severity
    sev_filter = await client.get(f"/api/v1/alerts?severity={first_alert['severity']}")
    assert sev_filter.status_code == 200
    assert all(a["severity"] == first_alert["severity"] for a in sev_filter.json()["data"])

    # 6. Filter by token_id
    token_filter = await client.get(f"/api/v1/alerts?token_id={token_id}")
    assert token_filter.status_code == 200
    assert len(token_filter.json()["data"]) >= 1

    # 7. Non-existent alert returns 404
    not_found = await client.get("/api/v1/alerts/non-existent-alert-uuid")
    assert not_found.status_code == 404
    assert not_found.json()["status"] == "error"
