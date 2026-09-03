from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from backend.services.event_stream import event_broadcaster

router = APIRouter(tags=["Real-Time Alert Streaming"])


@router.get(
    "/stream/alerts",
    summary="Real-Time Server-Sent Events (SSE) Alert Stream",
    description=(
        "Establishes a persistent Server-Sent Events connection. "
        "Broadcasts newly evaluated risk-scored alert events immediately to "
        "connected security dashboards with zero polling delay."
    ),
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "Continuous stream of JSON alert objects.",
            "content": {"text/event-stream": {}},
        }
    },
)
async def alert_event_stream():
    """
    Subscribes the client to the global alert event broadcaster.
    """
    return StreamingResponse(
        event_broadcaster.subscribe(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
