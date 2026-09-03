import pytest
from datetime import datetime, timezone
from backend.services.risk_scoring import (
    evaluate_contextual_time,
    evaluate_user_agent,
    determine_severity,
    SUSPICIOUS_USER_AGENTS,
)


def test_business_hours_weekday():
    # Tuesday at 09:30 UTC -> Business hours
    tue_work = datetime(2026, 9, 8, 9, 30, 0, tzinfo=timezone.utc)
    multiplier, reasons = evaluate_contextual_time(tue_work)
    assert multiplier == 1.0
    assert any("Standard business hours" in r for r in reasons)

    # Friday at 18:59 UTC -> Still business hours (< 19:00)
    fri_late = datetime(2026, 9, 11, 18, 59, 59, tzinfo=timezone.utc)
    multiplier, reasons = evaluate_contextual_time(fri_late)
    assert multiplier == 1.0


def test_off_hours_weekday_morning():
    # Wednesday at 07:45 UTC (< 08:00)
    wed_early = datetime(2026, 9, 9, 7, 45, 0, tzinfo=timezone.utc)
    multiplier, reasons = evaluate_contextual_time(wed_early)
    assert multiplier == 1.5
    assert any("Off-hours" in r for r in reasons)


def test_off_hours_weekday_night():
    # Thursday at 20:15 UTC (>= 19:00)
    thu_night = datetime(2026, 9, 10, 20, 15, 0, tzinfo=timezone.utc)
    multiplier, reasons = evaluate_contextual_time(thu_night)
    assert multiplier == 1.5
    assert any("Off-hours" in r for r in reasons)


def test_weekend_access():
    # Saturday afternoon
    sat_noon = datetime(2026, 9, 12, 12, 0, 0, tzinfo=timezone.utc)
    multiplier, reasons = evaluate_contextual_time(sat_noon)
    assert multiplier == 1.5
    assert any("Weekend" in r for r in reasons)

    # Sunday midnight
    sun_midnight = datetime(2026, 9, 13, 0, 30, 0, tzinfo=timezone.utc)
    multiplier, reasons = evaluate_contextual_time(sun_midnight)
    assert multiplier == 1.5
    assert any("Weekend" in r for r in reasons)


def test_user_agent_evaluation():
    # Suspicious tools (curl, requests, nmap, sqlmap, postman)
    for tool in ["curl/8.4.0", "python-requests/2.31.0", "PostmanRuntime/7.32.3", "sqlmap/1.7#stable", "Nmap Scripting Engine"]:
        mult, detected = evaluate_user_agent(tool)
        assert mult == 1.2
        assert detected is not None

    # Normal browser
    browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
    mult, detected = evaluate_user_agent(browser_ua)
    assert mult == 1.0
    assert detected is None

    # None / empty User-Agent
    mult_none, _ = evaluate_user_agent(None)
    assert mult_none == 1.0

    mult_empty, _ = evaluate_user_agent("")
    assert mult_empty == 1.0


def test_severity_classification_boundaries():
    # Low: 0 to 25.0
    assert determine_severity(0.0) == "Low"
    assert determine_severity(15.5) == "Low"
    assert determine_severity(25.0) == "Low"

    # Medium: 25.01 to 50.0
    assert determine_severity(25.01) == "Medium"
    assert determine_severity(37.5) == "Medium"
    assert determine_severity(50.0) == "Medium"

    # High: 50.01 to 75.0
    assert determine_severity(50.01) == "High"
    assert determine_severity(65.0) == "High"
    assert determine_severity(75.0) == "High"

    # Critical: > 75.0
    assert determine_severity(75.01) == "Critical"
    assert determine_severity(100.0) == "Critical"
    assert determine_severity(250.0) == "Critical"
