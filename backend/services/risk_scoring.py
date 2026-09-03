import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple, List, Optional
from sqlalchemy.orm import Session

from backend.models.token import HoneyToken
from backend.models.trigger import TokenTrigger
from backend.models.alert import AlertLog
from backend.services.event_stream import event_broadcaster


SUSPICIOUS_USER_AGENTS = [
    "curl",
    "python-requests",
    "httpx",
    "postman",
    "wget",
    "nmap",
    "nikto",
    "sqlmap",
    "insomnia",
    "go-http-client",
]


def evaluate_contextual_time(event_time: datetime) -> Tuple[float, List[str]]:
    """
    Sana Khan's Contextual Timestamp Evaluator.
    
    Examines trigger timestamp to differentiate normal business operations from
    illicit after-hours / weekend access by internal personnel:
    - Normal Business Hours: Monday–Friday, 08:00 to 19:00 local/UTC (1.0x multiplier)
    - Off-Hours / Weekend: Outside 08:00–19:00 or Saturday/Sunday (1.5x multiplier)

    Returns:
        (time_multiplier: float, audit_reasons: List[str])
    """
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    is_weekend = event_time.weekday() >= 5  # 5 = Saturday, 6 = Sunday
    is_off_hours = event_time.hour < 8 or event_time.hour >= 19

    reasons: List[str] = []
    if is_weekend or is_off_hours:
        multiplier = 1.5
        reason_parts = []
        if is_weekend:
            reason_parts.append(f"Weekend access ({event_time.strftime('%A')})")
        if is_off_hours:
            reason_parts.append(f"Outside business hours ({event_time.strftime('%H:%M')} outside 08:00-19:00)")
        reasons.append(f"Off-hours access modifier applied: {', '.join(reason_parts)} (1.5x)")
    else:
        multiplier = 1.0
        reasons.append("Standard business hours access (1.0x)")

    return multiplier, reasons


def evaluate_user_agent(user_agent: Optional[str]) -> Tuple[float, Optional[str]]:
    """
    Evaluates User-Agent string for signs of automated testing tools,
    pentest scanners, or script libraries.
    
    Returns:
        (tool_multiplier: float, detected_tool: Optional[str])
    """
    ua_str = (user_agent or "").lower()
    for tool in SUSPICIOUS_USER_AGENTS:
        if tool in ua_str:
            return 1.2, tool
    return 1.0, None


def evaluate_frequency(
    db: Session,
    token_id: str,
    source_ip: str,
    event_time: datetime,
    window_minutes: int = 5,
) -> Tuple[float, str, int]:
    """
    Calculates trigger burst frequency within a sliding time window
    for the specific token or originating source IP.
    
    Returns:
        (frequency_multiplier: float, reason_str: str, recent_hits: int)
    """
    cutoff = event_time - timedelta(minutes=window_minutes)
    cutoff_naive = cutoff.replace(tzinfo=None) if cutoff.tzinfo else cutoff

    recent_hits = (
        db.query(TokenTrigger)
        .filter(
            (TokenTrigger.token_id == token_id) | (TokenTrigger.source_ip == source_ip),
            TokenTrigger.triggered_at >= cutoff_naive,
        )
        .count()
    )

    if recent_hits <= 1:
        return 1.0, "Single isolated trigger (1.0x)", recent_hits
    elif recent_hits <= 4:
        return 1.3, f"Moderate burst activity: {recent_hits} hits in {window_minutes}m (1.3x)", recent_hits
    else:
        return 1.8, f"High-frequency burst / scanning: {recent_hits} hits in {window_minutes}m (1.8x)", recent_hits


def determine_severity(final_score: float) -> str:
    """
    Maps dynamic risk score to standardized severity tier:
    - 0 to 25.0: Low
    - 26.0 to 50.0: Medium
    - 51.0 to 75.0: High
    - > 75.0: Critical
    """
    if final_score <= 25.0:
        return "Low"
    elif final_score <= 50.0:
        return "Medium"
    elif final_score <= 75.0:
        return "High"
    else:
        return "Critical"


def calculate_risk_factors(
    token: HoneyToken,
    trigger: TokenTrigger,
    db: Session,
    window_minutes: int = 5,
) -> Tuple[float, str, Dict[str, Any]]:
    """
    Computes dynamic triage score using the multi-factor formula:
    Final Risk Score = W_asset * C_access * F_frequency

    Returns:
        (risk_score, severity, details_dict)
    """
    # 1. Base Asset Weight (W_asset): 1 to 50
    w_asset = float(token.criticality) if token.criticality else 10.0

    # 2. Context Modifier (C_access)
    event_time = trigger.triggered_at or datetime.now(timezone.utc)
    time_multiplier, context_reasons = evaluate_contextual_time(event_time)
    tool_multiplier, detected_tool = evaluate_user_agent(trigger.user_agent)

    if detected_tool:
        context_reasons.append(f"Automated tool / CLI User-Agent detected: {detected_tool} (1.2x)")

    c_access = round(time_multiplier * tool_multiplier, 2)

    # 3. Frequency Multiplier (F_frequency)
    f_freq, freq_reason, recent_hits = evaluate_frequency(
        db, token.token_id, trigger.source_ip, event_time, window_minutes
    )

    # Final Risk Score
    raw_score = w_asset * c_access * f_freq
    final_score = round(raw_score, 2)

    # Dynamic Severity Triage
    severity = determine_severity(final_score)

    details = {
        "asset_weight": w_asset,
        "context_multiplier": c_access,
        "context_reasons": context_reasons,
        "frequency_multiplier": f_freq,
        "frequency_reason": freq_reason,
        "recent_hits_in_window": recent_hits,
        "formula": f"Final Risk Score = W_asset ({w_asset}) * C_access ({c_access}) * F_frequency ({f_freq}) = {final_score}",
        "token_name": token.name,
        "token_type": token.token_type,
        "source_ip": trigger.source_ip,
        "user_agent": trigger.user_agent,
        "triggered_at": trigger.triggered_at.isoformat() if trigger.triggered_at else None,
    }

    return final_score, severity, details


def evaluate_and_log_alert(
    db: Session,
    trigger: TokenTrigger,
    token: HoneyToken,
) -> AlertLog:
    """
    Evaluates risk score for a trigger, persists the AlertLog record,
    and broadcasts the live alert event to connected SSE clients.
    """
    risk_score, severity, details = calculate_risk_factors(token, trigger, db)

    alert = AlertLog(
        alert_id=str(uuid.uuid4()),
        trigger_id=trigger.trigger_id,
        severity=severity,
        risk_score=risk_score,
        details=details,
        created_at=datetime.now(timezone.utc),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # Broadcast structured payload over Server-Sent Events
    alert_payload = {
        "alert_id": alert.alert_id,
        "trigger_id": alert.trigger_id,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "token_id": token.token_id,
        "token_name": token.name,
        "token_type": token.token_type,
        "source_ip": trigger.source_ip,
        "user_agent": trigger.user_agent,
        "created_at": alert.created_at.isoformat(),
        "details": details,
    }
    event_broadcaster.broadcast_sync("alert", alert_payload)

    return alert
