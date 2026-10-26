"""
Dynamic Multi-Factor Risk Scoring Engine (W x C x F)
CyberGuard SOC — Honeytoken-Based Insider Threat Detector
"""

from datetime import datetime
import re

# Base Asset Weights (W_asset: 1.0 to 50.0)
SENSITIVE_CLOUD_PATTERNS = [r"\.env", r"aws", r"stripe", r"key", r"secret", r"config\.ya?ml"]
FINANCIAL_PATTERNS = [r"\.pdf", r"payroll", r"salary", r"financial"]
CONFIDENTIAL_PATTERNS = [r"\.docx?", r"strategy", r"hr", r"confidential"]

# Suspicious CLI / Pentest tooling patterns in User-Agent
CLI_TOOL_PATTERNS = [
    r"curl",
    r"python-requests",
    r"urllib",
    r"postman",
    r"nmap",
    r"sqlmap",
    r"nikto",
    r"wget",
    r"httpx",
    r"burp",
]


def get_asset_weight(asset_name: str) -> float:
    """
    Calculate base asset sensitivity weight (1.0 to 50.0).
    - .env / aws / stripe / key / secret / config.yaml -> 45.0
    - .pdf / payroll / salary / financial -> 35.0
    - .docx / strategy / hr / confidential -> 30.0
    - Default URL / beacon token -> 25.0
    """
    if not asset_name:
        return 25.0

    name_lower = str(asset_name).lower()

    for pattern in SENSITIVE_CLOUD_PATTERNS:
        if re.search(pattern, name_lower):
            return 45.0

    for pattern in FINANCIAL_PATTERNS:
        if re.search(pattern, name_lower):
            return 35.0

    for pattern in CONFIDENTIAL_PATTERNS:
        if re.search(pattern, name_lower):
            return 30.0

    return 25.0


def get_context_multiplier(
    user_agent: str = "Unknown",
    access_time: datetime = None,
    force_off_hours: bool = False,
) -> float:
    """
    Calculate context multiplier (C_access):
    - Normal business hours (Mon-Fri, 08:00 to 18:59 local): 1.0
    - Off-hours (< 08:00 or >= 19:00) OR Weekend (weekday >= 5): 1.5
    - Automated CLI / Pentest tool in User-Agent: multiply by 1.2
    - Compound off-hours + CLI: 1.5 * 1.2 = 1.8
    """
    time_mult = 1.0

    if force_off_hours:
        time_mult = 1.5
    else:
        dt = access_time or datetime.now()
        # Monday is 0, Sunday is 6
        is_weekend = dt.weekday() >= 5
        is_off_hour = dt.hour < 8 or dt.hour >= 19
        if is_weekend or is_off_hour:
            time_mult = 1.5

    # Check for CLI tools
    tool_mult = 1.0
    ua_lower = (user_agent or "").lower()
    for pattern in CLI_TOOL_PATTERNS:
        if re.search(pattern, ua_lower):
            tool_mult = 1.2
            break

    return round(time_mult * tool_mult, 2)


def get_frequency_multiplier(recent_hits: int = 1) -> float:
    """
    Calculate access frequency multiplier (F_frequency) in last 5 minutes:
    - 1 hit: 1.0
    - 2 to 4 hits: 1.3
    - >= 5 hits: 1.8
    """
    hits = max(1, int(recent_hits))
    if hits >= 5:
        return 1.8
    elif hits >= 2:
        return 1.3
    return 1.0


def classify_severity(score: float) -> str:
    """
    Map final risk score to severity tier:
    - 0.0 <= score <= 25.0 -> Low
    - 25.0 < score <= 50.0 -> Medium
    - 50.0 < score <= 75.0 -> High
    - score > 75.0 -> Critical
    """
    if score > 75.0:
        return "Critical"
    elif score > 50.0:
        return "High"
    elif score > 25.0:
        return "Medium"
    return "Low"


def calculate_risk_score(
    asset_name: str,
    user_agent: str = "Unknown",
    recent_hits: int = 1,
    access_time: datetime = None,
    force_off_hours: bool = False,
) -> dict:
    """
    Calculate the dynamic multi-factor risk score:
    Final Risk Score = W_asset * C_access * F_frequency
    """
    w_asset = get_asset_weight(asset_name)
    c_access = get_context_multiplier(
        user_agent=user_agent,
        access_time=access_time,
        force_off_hours=force_off_hours,
    )
    f_frequency = get_frequency_multiplier(recent_hits)

    raw_score = w_asset * c_access * f_frequency
    final_score = round(raw_score, 2)
    severity = classify_severity(final_score)

    return {
        "risk_score": final_score,
        "severity": severity,
        "asset_weight": w_asset,
        "context_multiplier": c_access,
        "frequency_multiplier": f_frequency,
        "details": {
            "asset_name": asset_name,
            "user_agent": user_agent,
            "recent_hits": recent_hits,
            "force_off_hours": force_off_hours,
        },
    }
