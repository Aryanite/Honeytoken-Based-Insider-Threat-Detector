"""
Alert Management & Terminal Telemetry Dispatcher
CyberGuard SOC — Honeytoken-Based Insider Threat Detector
"""

import sys

# Ensure UTF-8 output on Windows terminal
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def generate_alert(event, risk_score: float = 25.0, severity: str = "High"):
    """
    Generate a security alert for a triggered honey token with dynamic risk triage.
    """
    token_display = event.get("token_id", "Unknown")
    ip_display = event.get("ip_address", "Unknown")
    time_display = event.get("triggered_at", "")

    alert = {
        "alert_type": "INSIDER_THREAT_HONEYTOKEN_TRIGGERED",
        "severity": severity,
        "risk_score": float(risk_score),
        "message": (
            f"Honeytoken {token_display} accessed from IP {ip_display} "
            f"[Risk Score: {risk_score:.1f} | Severity: {severity}]"
        ),
        "triggered_at": time_display,
    }

    try:
        print("\n" + "=" * 80)
        print("🚨 [CYBERGUARD-SOC] INSIDER THREAT HONEYTOKEN TRIGGERED | Risk Score & Telemetry Logged 🚨")
        print("=" * 80)
        print("Token ID    :", token_display)
        print("Source IP   :", ip_display)
        print("Risk Score  :", f"{risk_score:.2f}")
        print("Severity    :", severity)
        print("Tool / UA   :", event.get("user_agent", "Unknown"))
        print("Timestamp   :", time_display)
        print("=" * 80 + "\n")
    except UnicodeEncodeError:
        print("\n" + "=" * 80)
        print("[!] [CYBERGUARD-SOC] INSIDER THREAT HONEYTOKEN TRIGGERED | Risk Score & Telemetry Logged [!]")
        print("=" * 80)
        print("Token ID    :", token_display)
        print("Source IP   :", ip_display)
        print("Risk Score  :", f"{risk_score:.2f}")
        print("Severity    :", severity)
        print("Tool / UA   :", event.get("user_agent", "Unknown"))
        print("Timestamp   :", time_display)
        print("=" * 80 + "\n")

    return alert