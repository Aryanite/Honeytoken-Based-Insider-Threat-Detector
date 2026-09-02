import base64
from typing import Dict, Any, Tuple
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.models.token import HoneyToken
from backend.models.trigger import TokenTrigger

router = APIRouter(tags=["Beacon Telemetry"])

# Standard 1x1 transparent GIF (43 bytes)
TRANSPARENT_1X1_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)


def extract_client_telemetry(request: Request) -> Tuple[str, str, Dict[str, Any]]:
    """Extract client IP (with proxy handling), User-Agent, and sanitized headers."""
    # 1. Resolve source IP handling reverse proxies
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # First IP in X-Forwarded-For is the real client IP
        source_ip = forwarded_for.split(",")[0].strip()
    elif request.client and request.client.host:
        source_ip = request.client.host
    else:
        source_ip = "127.0.0.1"

    # 2. User-Agent
    user_agent = request.headers.get("user-agent", "Unknown")

    # 3. Capture headers (exclude sensitive headers if any)
    headers_dict = dict(request.headers)

    return source_ip, user_agent, headers_dict


@router.get(
    "/beacon/{token_id}",
    summary="Telemetry Beacon Endpoint",
    description="Public, unauthenticated listener capturing access attempts. Returns a 1x1 transparent GIF.",
    response_class=Response,
    responses={
        200: {
            "content": {"image/gif": {}},
            "description": "Returns 1x1 transparent GIF beacon",
        }
    },
)
def beacon_listener(
    token_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Handle incoming canary beacon triggers silently without breaking client applications."""
    source_ip, user_agent, headers_dict = extract_client_telemetry(request)

    # Check if token exists in database
    token = db.query(HoneyToken).filter(HoneyToken.token_id == token_id).first()

    if token and token.status == "active":
        # Log the access trigger event
        trigger = TokenTrigger(
            token_id=token.token_id,
            source_ip=source_ip,
            user_agent=user_agent,
            headers=headers_dict,
        )
        db.add(trigger)
        db.commit()

    # Always return 1x1 transparent GIF with anti-caching headers so client renders cleanly
    return Response(
        content=TRANSPARENT_1X1_GIF,
        media_type="image/gif",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )
