import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from backend.models.token import HoneyToken
from backend.models.trigger import TokenTrigger
from backend.services.risk_scoring import calculate_risk_factors, evaluate_and_log_alert


def test_risk_scoring_standard_business_hours(db_session: Session):
    token = HoneyToken(
        name="Standard Decoy",
        token_type="canary_doc",
        criticality=20,
        status="active",
    )
    db_session.add(token)
    db_session.commit()

    # Tuesday 14:00 (Business hours)
    tuesday_afternoon = datetime(2026, 9, 8, 14, 0, 0, tzinfo=timezone.utc)
    trigger = TokenTrigger(
        token_id=token.token_id,
        source_ip="192.168.1.10",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        triggered_at=tuesday_afternoon,
    )
    db_session.add(trigger)
    db_session.commit()

    score, severity, details = calculate_risk_factors(token, trigger, db_session)

    # W_asset = 20, C_access = 1.0, F_freq = 1.0 -> 20.0
    assert score == 20.0
    assert severity == "Low"
    assert details["asset_weight"] == 20.0
    assert details["context_multiplier"] == 1.0
    assert details["frequency_multiplier"] == 1.0


def test_risk_scoring_off_hours_and_curl_multiplier(db_session: Session):
    token = HoneyToken(
        name="Executive Salary Memo",
        token_type="canary_doc",
        criticality=40,
        status="active",
    )
    db_session.add(token)
    db_session.commit()

    # Sunday night 23:30 + curl User-Agent
    sunday_night = datetime(2026, 9, 6, 23, 30, 0, tzinfo=timezone.utc)
    trigger = TokenTrigger(
        token_id=token.token_id,
        source_ip="10.0.0.5",
        user_agent="curl/7.88.1",
        triggered_at=sunday_night,
    )
    db_session.add(trigger)
    db_session.commit()

    score, severity, details = calculate_risk_factors(token, trigger, db_session)

    # W_asset = 40, C_access = 1.5 (off-hours) * 1.2 (curl) = 1.8, F_freq = 1.0
    # Expected: 40 * 1.8 * 1.0 = 72.0 -> "High"
    assert score == 72.0
    assert severity == "High"
    assert details["context_multiplier"] == 1.8
    assert any("Off-hours" in r for r in details["context_reasons"])
    assert any("curl" in r for r in details["context_reasons"])


def test_risk_scoring_burst_frequency_escalation(db_session: Session):
    token = HoneyToken(
        name="High Value Core Secret",
        token_type="api_key",
        criticality=45,
        status="active",
    )
    db_session.add(token)
    db_session.commit()

    now = datetime.now(timezone.utc)
    # Simulate 5 rapid hits from the same IP within last 2 minutes
    for i in range(5):
        trig = TokenTrigger(
            token_id=token.token_id,
            source_ip="198.51.100.77",
            user_agent="python-requests/2.31.0",
            triggered_at=now - timedelta(seconds=i * 10),
        )
        db_session.add(trig)
    db_session.commit()

    latest_trigger = TokenTrigger(
        token_id=token.token_id,
        source_ip="198.51.100.77",
        user_agent="python-requests/2.31.0",
        triggered_at=now,
    )
    db_session.add(latest_trigger)
    db_session.commit()

    score, severity, details = calculate_risk_factors(token, latest_trigger, db_session)

    # 6 hits in window -> F_freq = 1.8
    assert details["frequency_multiplier"] == 1.8
    # Score exceeds 75 -> Critical
    assert score > 75.0
    assert severity == "Critical"


def test_evaluate_and_log_alert_persists_record(db_session: Session):
    token = HoneyToken(
        name="Persist Alert Decoy",
        token_type="db_record",
        criticality=30,
        status="active",
    )
    db_session.add(token)
    db_session.commit()

    trigger = TokenTrigger(
        token_id=token.token_id,
        source_ip="172.16.0.4",
        user_agent="CustomProber/1.0",
        triggered_at=datetime.now(timezone.utc),
    )
    db_session.add(trigger)
    db_session.commit()

    alert = evaluate_and_log_alert(db_session, trigger, token)
    assert alert.alert_id is not None
    assert alert.trigger_id == trigger.trigger_id
    assert alert.severity in ["Low", "Medium", "High", "Critical"]
    assert alert.details["token_name"] == "Persist Alert Decoy"
