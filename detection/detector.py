import sys
from datetime import datetime
from flask import request

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def create_detection_event(token_id):
    """
    Create an event containing telemetry information about
    the request that triggered a honey token.
    """
    event = {
        "token_id": token_id,
        "triggered_at": datetime.now().isoformat(),
        "ip_address": request.remote_addr,
        "request_method": request.method,
        "user_agent": request.headers.get("User-Agent", "Unknown"),
        "status": "TRIGGERED"
    }

    return event


def print_detection_alert(event):
    """
    Display the detected honeytoken access telemetry in the application terminal.
    """
    try:
        print("\n" + "=" * 60)
        print("🚨 CYBERGUARD SOC · HONEYTOKEN ACCESS DETECTED 🚨")
        print("=" * 60)
        print("Token ID      :", event.get("token_id"))
        print("Triggered At  :", event.get("triggered_at"))
        print("IP Address    :", event.get("ip_address"))
        print("Request Method:", event.get("request_method"))
        print("User Agent    :", event.get("user_agent"))
        print("Status        :", event.get("status"))
        print("=" * 60)
    except UnicodeEncodeError:
        print("\n" + "=" * 60)
        print("[!] CYBERGUARD SOC · HONEYTOKEN ACCESS DETECTED [!]")
        print("=" * 60)
        print("Token ID      :", event.get("token_id"))
        print("Triggered At  :", event.get("triggered_at"))
        print("IP Address    :", event.get("ip_address"))
        print("Request Method:", event.get("request_method"))
        print("User Agent    :", event.get("user_agent"))
        print("Status        :", event.get("status"))
        print("=" * 60)