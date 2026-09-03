import asyncio
import pytest
from httpx import AsyncClient
from backend.core.rate_limiter import SlidingWindowRateLimiter


def test_sliding_window_rate_limiter_logic():
    limiter = SlidingWindowRateLimiter(default_limit=5, default_window_seconds=10)
    key = "test_ip_1"

    # 5 requests should pass
    for i in range(5):
        allowed, count, retry_after = limiter.is_allowed(key)
        assert allowed is True
        assert count == i + 1

    # 6th request should fail
    allowed, count, retry_after = limiter.is_allowed(key)
    assert allowed is False
    assert retry_after > 0


@pytest.mark.asyncio
async def test_concurrent_beacon_triggers_stress(client: AsyncClient):
    # 1. Create active token
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Stress Test Canary Doc",
        "token_type": "canary_doc",
        "criticality": 40,
    })
    token_id = create_res.json()["data"]["token_id"]

    # 2. Fire 10 concurrent requests from different IPs
    async def hit_beacon(ip_suffix: int):
        headers = {
            "X-Forwarded-For": f"10.50.0.{ip_suffix}",
            "User-Agent": f"ConcurrentSimClient/{ip_suffix}",
        }
        return await client.get(f"/beacon/{token_id}", headers=headers)

    tasks = [hit_beacon(i) for i in range(10)]
    responses = await asyncio.gather(*tasks)

    for res in responses:
        assert res.status_code == 200
        assert res.headers["content-type"] == "image/gif"

    # 3. Check that triggers and alerts were logged
    stats_res = await client.get("/api/v1/dashboard/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()["data"]
    assert stats["total_triggers"] >= 10
    assert stats["total_alerts"] >= 10
