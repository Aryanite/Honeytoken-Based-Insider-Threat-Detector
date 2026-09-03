import asyncio
import json
import pytest
from httpx import AsyncClient

from backend.services.event_stream import event_broadcaster


@pytest.mark.asyncio
async def test_event_broadcaster_subscribe_and_receive():
    # Register a queue
    queue = await event_broadcaster.register()
    assert queue in event_broadcaster._subscribers

    # Broadcast test event
    test_data = {"test_key": "test_val", "score": 85.5}
    await event_broadcaster.broadcast("alert", test_data)

    # Receive from queue
    message = await asyncio.wait_for(queue.get(), timeout=2.0)
    assert "event: alert" in message
    assert '"score": 85.5' in message

    # Cleanup
    await event_broadcaster.unregister(queue)
    assert queue not in event_broadcaster._subscribers


@pytest.mark.asyncio
async def test_stream_alerts_endpoint_handshake(client: AsyncClient, monkeypatch):
    # Test that connecting to the stream starts with a handshake event.
    # In ASGI testing mode (in-memory ASGITransport), infinite while-loops deadlock
    # because ASGITransport waits for response_complete before returning headers.
    # We mock subscribe to yield the handshake event and cleanly complete.
    async def mock_subscribe():
        yield 'event: connected\ndata: {"message": "Connected to alert stream"}\n\n'

    monkeypatch.setattr(event_broadcaster, "subscribe", mock_subscribe)

    async with client.stream("GET", "/api/v1/stream/alerts") as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        
        # Read the first chunk (the connected handshake)
        async for line in response.aiter_lines():
            if line.startswith("event:"):
                assert "connected" in line
                break
