import asyncio
import json
import logging
from typing import AsyncGenerator, Set, Dict, Any, Optional

logger = logging.getLogger("event_stream")


class EventBroadcaster:
    """
    Publish-Subscribe dispatcher for real-time Server-Sent Events (SSE).
    Distributes newly triage-scored alerts to all connected dashboard sessions.
    """

    def __init__(self):
        self._subscribers: Set[asyncio.Queue] = set()
        self._lock: Optional[asyncio.Lock] = None

    @property
    def lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def register(self) -> asyncio.Queue:
        """Register a new listener queue for an incoming SSE connection."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        async with self.lock:
            self._subscribers.add(queue)
        logger.info(f"New dashboard SSE subscriber registered. Total active: {len(self._subscribers)}")
        return queue

    async def unregister(self, queue: asyncio.Queue) -> None:
        """Remove a subscriber queue when client disconnects."""
        async with self.lock:
            self._subscribers.discard(queue)
        logger.info(f"Dashboard SSE subscriber disconnected. Total active: {len(self._subscribers)}")

    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """Asynchronously push an event to all active subscriber queues."""
        raw_message = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"

        async with self.lock:
            dead_queues = []
            for queue in self._subscribers:
                try:
                    queue.put_nowait(raw_message)
                except asyncio.QueueFull:
                    dead_queues.append(queue)
            for dead in dead_queues:
                self._subscribers.discard(dead)

    def broadcast_sync(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        Thread-safe synchronous broadcast dispatch.
        Can be called from synchronous database handlers or background workers.
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(event_type, data))
        except RuntimeError:
            try:
                asyncio.run(self.broadcast(event_type, data))
            except Exception as e:
                logger.warning(f"Could not broadcast alert event: {e}")

    async def subscribe(self) -> AsyncGenerator[str, None]:
        """
        Async generator yielding SSE data chunks to a streaming response.
        Sends an initial handshake ping, then streams incoming alerts.
        """
        queue = await self.register()
        # Initial connection handshake
        yield f"event: connected\ndata: {json.dumps({'message': 'Connected to alert stream'})}\n\n"

        try:
            while True:
                message = await queue.get()
                yield message
        except asyncio.CancelledError:
            pass
        finally:
            await self.unregister(queue)

    @property
    def active_subscribers_count(self) -> int:
        return len(self._subscribers)


# Global singleton event broadcaster
event_broadcaster = EventBroadcaster()
