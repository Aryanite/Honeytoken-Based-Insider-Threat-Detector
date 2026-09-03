from typing import Optional
from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.models.token import HoneyToken
from backend.models.trigger import TokenTrigger
from backend.routes.beacon import _extract_client_telemetry
from backend.services.risk_scoring import evaluate_and_log_alert
from backend.core.rate_limiter import rate_limiter
from backend.schemas.auth_verify import AuthVerifyRequestSchema
from backend.schemas.envelope import error_response

router = APIRouter(tags=["Credential Verification Decoy"])


@router.post(
    "/auth/verify",
    summary="Mock Credential Verification Gateway",
    description=(
        "Simulates an internal authentication/service verification endpoint. "
        "Captures unauthorized attempts by insider actors testing leaked decoy API keys. "
        "When an active canary key is tested, telemetry is captured, dynamic risk scoring is "
        "calculated, an alert is broadcast to the dashboard, and a realistic 401 is returned."
    ),
    responses={
        200: {"description": "Credential verified successfully."},
        401: {"description": "Invalid, expired, or revoked credentials."},
        429: {"description": "Rate limit exceeded."},
    },
)
async def verify_credentials(
    request: Request,
    payload: Optional[AuthVerifyRequestSchema] = None,
    api_key: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Response:
    """
    Examines incoming requests for decoy API keys:
    1. Checks Authorization header (Bearer <token>)
    2. Checks X-API-Key header
    3. Checks JSON body {'api_key': '...'}
    4. Checks query string ?api_key=...
    """
    source_ip, user_agent, headers_dict = _extract_client_telemetry(request)

    # Sliding-window rate limit (100 req/min per IP on auth verification)
    allowed, count, retry_after = rate_limiter.is_allowed(f"auth:{source_ip}", limit=100, window_seconds=60)
    if not allowed:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=error_response(f"Too many verification attempts. Please retry in {retry_after} seconds.").model_dump(),
            headers={"Retry-After": str(int(retry_after))},
        )

    # Resolve candidate key
    candidate_key = None

    # Check Authorization header: "Bearer <token>"
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        candidate_key = auth_header[7:].strip()
    elif auth_header.lower().startswith("token "):
        candidate_key = auth_header[6:].strip()

    # Check X-API-Key header
    if not candidate_key:
        candidate_key = request.headers.get("x-api-key")

    # Check request JSON payload
    if not candidate_key and payload and payload.api_key:
        candidate_key = payload.api_key.strip()

    # Check query parameter fallback
    if not candidate_key and api_key:
        candidate_key = api_key.strip()

    if not candidate_key:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=error_response("No credential token provided for verification.").model_dump(),
        )

    # Query HoneyToken table for this key
    # Also support matching by token_id or if key format is "ak_live_<token_id>"
    clean_key = candidate_key
    if clean_key.startswith("ak_live_") or clean_key.startswith("AKIA-"):
        clean_key = clean_key.split("-")[1] if "-" in clean_key else clean_key.replace("ak_live_", "")

    token = (
        db.query(HoneyToken)
        .filter(
            (HoneyToken.token_id == candidate_key)
            | (HoneyToken.token_id == clean_key)
            | (HoneyToken.token_id.like(f"{clean_key}%"))
        )
        .first()
    )

    # If it is an ACTIVE honeytoken, capture telemetry and trigger risk scoring
    if token and token.status == "active":
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

    # Always return a realistic 401 Unauthorized so the rogue actor believes the key
    # simply lacks permissions or has expired, leaving them unaware of detection.
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content=error_response("The provided credentials are invalid, revoked, or lack necessary IAM privileges.").model_dump(),
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )
