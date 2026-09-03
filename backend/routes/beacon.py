import base64
from typing import Dict, Any, Tuple
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.models.token import HoneyToken
from backend.models.trigger import TokenTrigger
from backend.services.risk_scoring import evaluate_and_log_alert
from backend.core.rate_limiter import rate_limiter

router = APIRouter(tags=["Beacon Telemetry"])

# Standard 1x1 pixel transparent GIF payload
# Base64: R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7
TRANSPARENT_1X1_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)


def _extract_client_telemetry(request: Request) -> Tuple[str, str, Dict[str, Any]]:
    """
    Extract client IP, User-Agent, and sanitized headers from an incoming request.

    IP resolution respects the X-Forwarded-For header for reverse-proxy environments:
    the leftmost entry in XFF is the originating client IP.
    """
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        source_ip = forwarded_for.split(",")[0].strip()
    elif request.client and request.client.host:
        source_ip = request.client.host
    else:
        source_ip = "0.0.0.0"

    user_agent = request.headers.get("user-agent", "Unknown")

    # Capture all headers as a plain dict for JSON storage
    headers_dict: Dict[str, Any] = dict(request.headers)

    return source_ip, user_agent, headers_dict


@router.get(
    "/beacon/{token_id}",
    summary="Telemetry Beacon Endpoint",
    description=(
        "Public, unauthenticated endpoint. Captures access metadata and returns a "
        "1x1 transparent GIF so the trigger is invisible to the accessing client. "
        "Automatically routes active triggers into the dynamic risk-scoring pipeline."
    ),
    response_class=Response,
    responses={
        200: {
            "content": {"image/gif": {}},
            "description": "Always returns a 1x1 transparent GIF beacon image.",
        }
    },
)
def beacon_listener(
    token_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    """
    Telemetry receiver for honeytoken access events.

    - Rate-limited per source IP using a sliding-window algorithm.
    - Logs a TokenTrigger record for any ACTIVE honeytoken that is accessed.
    - Triggers dynamic risk-scoring evaluation and real-time alert dispatch.
    - Revoked or non-existent tokens are silently ignored (no trigger logged).
    - Always returns a 1x1 transparent GIF regardless of token state to avoid
      exposing information about the presence or status of a decoy to the accessor.
    """
    source_ip, user_agent, headers_dict = _extract_client_telemetry(request)

    # Check sliding window rate limiter (60 req / min per IP)
    allowed, count, retry_after = rate_limiter.is_allowed(
        f"beacon:{source_ip}", limit=60, window_seconds=60
    )

    token = db.query(HoneyToken).filter(HoneyToken.token_id == token_id).first()

    # Only log if token is active and not aggressively rate-banned
    if token and token.status == "active" and allowed:
        trigger = TokenTrigger(
            token_id=token.token_id,
            source_ip=source_ip,
            user_agent=user_agent,
            headers=headers_dict,
        )
        db.add(trigger)
        db.commit()
        db.refresh(trigger)

        # Trigger dynamic risk scoring and real-time alert dispatch
        evaluate_and_log_alert(db, trigger, token)

    return Response(
        content=TRANSPARENT_1X1_GIF,
        media_type="image/gif",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )
