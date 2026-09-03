from datetime import datetime, timezone, time
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.db.session import get_db
from backend.models.token import HoneyToken
from backend.models.trigger import TokenTrigger
from backend.models.alert import AlertLog
from backend.schemas.envelope import ApiResponse, success_response
from backend.schemas.dashboard import (
    DashboardStatsSchema,
    MetricCardsSchema,
    SeverityBreakdownSchema,
    TokenTypeBreakdownSchema,
    RecentAlertSummarySchema,
)

router = APIRouter(prefix="/dashboard", tags=["Security Dashboard & Analytics"])


@router.get(
    "/stats",
    response_model=ApiResponse[DashboardStatsSchema],
    summary="Get Security Dashboard Aggregated Metrics",
    description=(
        "Returns system-wide operational metrics: active vs. revoked decoy counts, "
        "today's triggers, critical severity threats, severity distribution, "
        "asset type breakdown, and recent alert event summaries for dashboard display."
    ),
)
def get_dashboard_stats(db: Session = Depends(get_db)):
    # 1. Asset metrics
    total_decoys = db.query(HoneyToken).count()
    active_decoys = db.query(HoneyToken).filter(HoneyToken.status == "active").count()
    revoked_decoys = db.query(HoneyToken).filter(HoneyToken.status == "revoked").count()

    # 2. Trigger metrics
    total_triggers = db.query(TokenTrigger).count()
    total_alerts = db.query(AlertLog).count()
    now_utc = datetime.now(timezone.utc)
    today_start = datetime.combine(now_utc.date(), time.min).replace(tzinfo=timezone.utc)
    today_start_naive = today_start.replace(tzinfo=None)

    today_triggers = (
        db.query(TokenTrigger)
        .filter(TokenTrigger.triggered_at >= today_start_naive)
        .count()
    )

    # 3. Severity breakdown & Critical count
    severity_counts = (
        db.query(AlertLog.severity, func.count(AlertLog.alert_id))
        .group_by(AlertLog.severity)
        .all()
    )
    sev_map = {sev: count for sev, count in severity_counts}
    low_sev = sev_map.get("Low", 0)
    med_sev = sev_map.get("Medium", 0)
    high_sev = sev_map.get("High", 0)
    crit_sev = sev_map.get("Critical", 0)

    # 4. Token type breakdown
    type_counts = (
        db.query(HoneyToken.token_type, func.count(HoneyToken.token_id))
        .group_by(HoneyToken.token_type)
        .all()
    )
    type_map = {tt: count for tt, count in type_counts}
    api_keys = type_map.get("api_key", 0)
    canary_docs = type_map.get("canary_doc", 0)
    db_records = type_map.get("db_record", 0)

    # 5. Recent alerts (most recent 20)
    recent_alerts_orm = (
        db.query(AlertLog)
        .join(TokenTrigger, AlertLog.trigger_id == TokenTrigger.trigger_id)
        .join(HoneyToken, TokenTrigger.token_id == HoneyToken.token_id)
        .order_by(AlertLog.created_at.desc())
        .limit(20)
        .all()
    )

    recent_alert_summaries: List[RecentAlertSummarySchema] = []
    for a in recent_alerts_orm:
        t_trigger = a.trigger
        t_token = t_trigger.token if t_trigger else None
        token_id_str = t_token.token_id if t_token else (t_trigger.token_id if t_trigger else "")
        recent_alert_summaries.append(
            RecentAlertSummarySchema(
                alert_id=a.alert_id,
                token_id=token_id_str,
                token_name=t_token.name if t_token else "Unknown Decoy",
                token_type=t_token.token_type if t_token else "unknown",
                severity=a.severity,
                risk_score=a.risk_score,
                source_ip=t_trigger.source_ip if t_trigger else "0.0.0.0",
                triggered_at=(
                    t_trigger.triggered_at.isoformat()
                    if t_trigger and t_trigger.triggered_at
                    else a.created_at.isoformat()
                ),
            )
        )

    stats_data = DashboardStatsSchema(
        total_triggers=total_triggers,
        total_alerts=total_alerts,
        active_tokens=active_decoys,
        total_tokens=total_decoys,
        critical_alerts=crit_sev,
        metrics=MetricCardsSchema(
            active_decoys=active_decoys,
            total_decoys=total_decoys,
            revoked_decoys=revoked_decoys,
            today_triggers=today_triggers,
            total_triggers=total_triggers,
            critical_threats=crit_sev,
        ),
        severity_breakdown=SeverityBreakdownSchema(
            low=low_sev,
            medium=med_sev,
            high=high_sev,
            critical=crit_sev,
        ),
        token_type_breakdown=TokenTypeBreakdownSchema(
            api_key=api_keys,
            canary_doc=canary_docs,
            db_record=db_records,
        ),
        recent_alerts=recent_alert_summaries,
        generated_at=now_utc.isoformat(),
    )

    return success_response(stats_data)
