from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.models.alert import AlertLog
from backend.models.trigger import TokenTrigger
from backend.schemas.envelope import ApiResponse, success_response
from backend.schemas.alert import AlertLogResponseSchema, SeverityLevel

router = APIRouter(prefix="/alerts", tags=["Alerts & Triage Incident Log"])


@router.get(
    "",
    response_model=ApiResponse[List[AlertLogResponseSchema]],
    summary="List Triage Alerts",
    description="Retrieve historical alert records with optional severity and token filters.",
)
def list_alerts(
    severity: Optional[SeverityLevel] = Query(None, description="Filter by triage severity (Low, Medium, High, Critical)"),
    token_id: Optional[str] = Query(None, description="Filter alerts for a specific honeytoken UUID"),
    limit: int = Query(50, ge=1, le=200, description="Max alerts to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
):
    query = db.query(AlertLog)
    if severity:
        query = query.filter(AlertLog.severity == severity)
    if token_id:
        query = query.join(TokenTrigger, AlertLog.trigger_id == TokenTrigger.trigger_id).filter(
            TokenTrigger.token_id == token_id
        )

    alerts = query.order_by(AlertLog.created_at.desc()).offset(offset).limit(limit).all()
    return success_response([AlertLogResponseSchema.model_validate(a) for a in alerts])


@router.get(
    "/{alert_id}",
    response_model=ApiResponse[AlertLogResponseSchema],
    summary="Get Alert Details",
    description="Retrieve an individual alert log record including its full analytical score breakdown.",
)
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(AlertLog).filter(AlertLog.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert record '{alert_id}' not found.",
        )
    return success_response(AlertLogResponseSchema.model_validate(alert))
