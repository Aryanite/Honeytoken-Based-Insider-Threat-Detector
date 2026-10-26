import base64
import ipaddress
import json
import os
import queue
import secrets
import socket
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime
from functools import wraps

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is at the head of sys.path when invoked via `python app/app.py`
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)

from alerts.alert_manager import generate_alert
from alerts.risk_scoring import calculate_risk_score
from database.admin_auth import (
    change_password,
    ensure_admin,
    username,
    verify_credentials,
)
from database.database import (
    block_ip,
    create_database,
    get_all_events,
    get_blocked_ips,
    get_dashboard_stats,
    get_recent_hit_count,
    is_ip_blocked,
    save_event,
    unblock_ip,
)
from detection.detector import create_detection_event, print_detection_alert
from detection.rate_limiter import rate_limiter
from honeytokens.file_honeytoken import generate_file_honeytoken
from honeytokens.generator import generate_honey_token

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN_FILE = os.path.join(BASE_DIR, "honeytokens", "tokens.json")

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.secret_key = os.environ.get("CYBERGUARD_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# Initialize database and default admin account
create_database()
ensure_admin()

# 43-byte base64-decoded transparent 1x1 GIF
TRANSPARENT_1X1_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="
)

# SSE subscriber queue pool
_sse_subscribers = []
_sse_lock = threading.Lock()


def broadcast_sse_event(event_dict):
    """Broadcast an alert event to all active SSE subscribers."""
    with _sse_lock:
        dead_queues = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(event_dict)
            except Exception:
                dead_queues.append(q)
        for q in dead_queues:
            if q in _sse_subscribers:
                _sse_subscribers.remove(q)


def load_tokens():
    if not os.path.exists(TOKEN_FILE):
        return []
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def save_tokens(tokens):
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=4)


def system_lan_ip():
    """Return this computer's active LAN address without relying on a hard-coded IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        sock.close()


def get_client_ip():
    """Extract client IP, checking X-Forwarded-For header first for proxies."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    remote = request.remote_addr or "Unknown"
    if remote in {"127.0.0.1", "::1"}:
        return system_lan_ip()
    return remote


def lookup_location(ip_address):
    """Resolve IP geolocation, skipping private and local ranges."""
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "Private / Local Network"
    except ValueError:
        return "Unknown"
    try:
        req = urllib.request.Request(
            f"https://ipwho.is/{ip_address}",
            headers={"User-Agent": "CyberGuard-SOC/1.0"},
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode("utf-8"))
        if data.get("success"):
            parts = [data.get("city"), data.get("region"), data.get("country")]
            return ", ".join([x for x in parts if x]) or "Unknown"
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass
    return "Location unavailable"


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_authenticated"):
            if request.path.startswith("/api/"):
                return (
                    jsonify({"success": False, "message": "Admin authentication required."}),
                    401,
                )
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def build_dashboard_payload():
    events = get_all_events()
    stats = get_dashboard_stats()
    tokens = load_tokens()
    active = sum(1 for t in tokens if t.get("status") == "ACTIVE")
    triggered = sum(1 for t in tokens if t.get("status") == "TRIGGERED")
    revoked = sum(1 for t in tokens if t.get("status") == "REVOKED")
    blocked = [dict(r) for r in get_blocked_ips()]
    token_map = {t.get("token_id"): t for t in tokens}

    serial = []
    for e in events:
        row = dict(e)
        t = token_map.get(row.get("token_id"), {})
        row["resource_name"] = t.get("filename") or t.get("token_id") or row.get("token_id") or "Unknown resource"
        row["token_type"] = t.get("token_type", "URL")
        row["trigger_url"] = t.get("trigger_url", f"/beacon/{row.get('token_id', '')}")
        # Ensure risk_score and severity are populated
        row["risk_score"] = float(row.get("risk_score") or 0.0)
        row["severity"] = row.get("severity") or "High"
        serial.append(row)

    counts = {}
    for r in serial:
        name = r["resource_name"]
        counts[name] = counts.get(name, 0) + 1

    resources = []
    for t in reversed(tokens):
        resources.append({
            "token_id": t.get("token_id"),
            "filename": t.get("filename") or t.get("token_id"),
            "token_type": t.get("token_type", "URL"),
            "created_at": t.get("created_at"),
            "status": t.get("status", "ACTIVE"),
            "trigger_url": t.get("trigger_url") or f"/beacon/{t.get('token_id')}",
        })

    return {
        "stats": {
            "total_tokens": len(tokens),
            "active_tokens": active,
            "triggered_tokens": triggered,
            "revoked_tokens": revoked,
            "total_incidents": stats["total_incidents"],
            "high_alerts": stats["high_alerts"],
            "unique_ips": stats["unique_ips"],
            "blocked_ips": stats["blocked_ips"],
        },
        "events": serial,
        "resources": resources,
        "blocked_ips": blocked,
        "incident_labels": list(counts.keys()),
        "incident_values": list(counts.values()),
    }


# ============================================================================
# Routes: Core Endpoints & Deception Handlers
# ============================================================================

@app.route("/")
def home():
    return redirect(url_for("user_dashboard"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_authenticated"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if verify_credentials(u, p):
            session["admin_authenticated"] = True
            session["admin_username"] = username()
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid administrator credentials.", "error")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/change-password", methods=["POST"])
@admin_required
def admin_change_password():
    ok, message = change_password(
        request.form.get("current_password", ""),
        request.form.get("new_password", ""),
    )
    flash(message, "success" if ok else "error")
    return redirect(url_for("dashboard"))


@app.route("/user-dashboard")
def user_dashboard():
    tokens = [t for t in load_tokens() if t.get("token_type") == "FILE"]
    return render_template("user_dashboard.html", tokens=tokens)


@app.route("/generate-token")
@admin_required
def generate_token():
    token = generate_honey_token()
    return jsonify({
        "message": "New CyberGuard Honey Token Generated Successfully",
        "token": token,
        "trigger_url": f"/beacon/{token['token_id']}",
    })


@app.route("/generate-file-token")
@admin_required
def generate_file_token():
    filename = request.args.get("filename", "Executive_Payroll_2026.pdf").strip()
    token = generate_file_honeytoken(
        filename or "Executive_Payroll_2026.pdf",
        server_ip=system_lan_ip(),
    )
    return jsonify({
        "message": "CyberGuard File Honey Token Generated Successfully",
        "token": token,
        "trigger_url": f"/beacon/{token['token_id']}",
    })


@app.route("/api/revoke-token", methods=["POST"])
@admin_required
def api_revoke_token():
    """Revoke an active honeytoken so subsequent accesses do not log false alerts."""
    data = request.get_json(silent=True) or {}
    token_id = str(data.get("token_id", "")).strip()
    if not token_id:
        return jsonify({"success": False, "message": "token_id is required"}), 400

    tokens = load_tokens()
    found = False
    for t in tokens:
        if t.get("token_id") == token_id:
            t["status"] = "REVOKED"
            found = True
            break

    if not found:
        return jsonify({"success": False, "message": "Token not found"}), 404

    save_tokens(tokens)
    return jsonify({"success": True, "message": f"Token {token_id} has been revoked."})


# ============================================================================
# Telemetry Beacon & Trap Routes
# ============================================================================

@app.route("/beacon/<token_id>", methods=["GET"])
def beacon_listener(token_id):
    """
    Covert 1x1 GIF Beacon Route:
    - Extracts client IP (respecting X-Forwarded-For).
    - Checks IP Blocklist.
    - Rate limits DoS burst requests.
    - If token exists and is REVOKED: returns 1x1 GIF silently with zero alert.
    - If token is active: computes dynamic risk score (W x C x F), logs incident,
      marks token TRIGGERED, broadcasts via SSE, and returns transparent 1x1 GIF.
    """
    client_ip = get_client_ip()

    # Rate limiting check
    if not rate_limiter.is_allowed(client_ip):
        # Return 1x1 GIF silently on rate-limit throttle to protect server from flooding
        resp = Response(TRANSPARENT_1X1_GIF, mimetype="image/gif", status=200)
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return resp

    # IP Blocking check
    if is_ip_blocked(client_ip):
        return jsonify({"message": "Request blocked by administrator", "ip_address": client_ip, "status": "BLOCKED"}), 403

    tokens = load_tokens()
    token = next((t for t in tokens if t.get("token_id") == token_id), None)

    if not token:
        # Invalid token ID: return 404
        return jsonify({"message": "Invalid Honey Token"}), 404

    # If the token has been revoked by security admin, return GIF without raising false alerts
    if token.get("status") == "REVOKED":
        resp = Response(TRANSPARENT_1X1_GIF, mimetype="image/gif", status=200)
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return resp

    # Active token trigger: mark triggered and save
    token["status"] = "TRIGGERED"
    save_tokens(tokens)

    # Compute dynamic multi-factor risk score (W x C x F)
    asset_name = token.get("filename") or token.get("token_id") or "URL_Beacon"
    user_agent = request.headers.get("User-Agent", "Unknown")
    recent_hits = get_recent_hit_count(client_ip, minutes=5) + 1
    risk_data = calculate_risk_score(
        asset_name=asset_name,
        user_agent=user_agent,
        recent_hits=recent_hits,
    )

    location = lookup_location(client_ip)
    now_iso = datetime.now().isoformat()

    # Log to SQLite
    save_event(
        token_id=token_id,
        triggered_at=now_iso,
        ip_address=client_ip,
        request_method=request.method,
        user_agent=user_agent,
        alert_type="INSIDER_THREAT_BEACON_TRIGGERED",
        severity=risk_data["severity"],
        message=f"Beacon accessed for {asset_name} [Risk Score: {risk_data['risk_score']}]",
        location=location,
        risk_score=risk_data["risk_score"],
    )

    # Terminal alert banner
    event_payload = {
        "token_id": token_id,
        "triggered_at": now_iso,
        "ip_address": client_ip,
        "request_method": request.method,
        "user_agent": user_agent,
        "status": "TRIGGERED",
        "risk_score": risk_data["risk_score"],
        "severity": risk_data["severity"],
        "resource_name": asset_name,
        "location": location,
    }
    generate_alert(event_payload, risk_score=risk_data["risk_score"], severity=risk_data["severity"])

    # Broadcast via SSE
    broadcast_sse_event(event_payload)

    resp = Response(TRANSPARENT_1X1_GIF, mimetype="image/gif", status=200)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp


@app.route("/honeytoken/<token_id>", methods=["GET"])
def trigger_honeytoken(token_id):
    """Legacy compatibility URL route that forwards to the risk scoring pipeline."""
    client_ip = get_client_ip()
    if is_ip_blocked(client_ip):
        return jsonify({"message": "Request blocked by administrator", "ip_address": client_ip, "status": "BLOCKED"}), 403

    tokens = load_tokens()
    token = next((t for t in tokens if t.get("token_id") == token_id), None)
    if not token:
        return jsonify({"message": "Invalid Honey Token"}), 404

    if token.get("status") == "REVOKED":
        return jsonify({"message": "Token has been revoked", "status": "REVOKED"})

    token["status"] = "TRIGGERED"
    save_tokens(tokens)

    asset_name = token.get("filename") or token.get("token_id") or "URL_Beacon"
    user_agent = request.headers.get("User-Agent", "Unknown")
    recent_hits = get_recent_hit_count(client_ip, minutes=5) + 1
    risk_data = calculate_risk_score(asset_name, user_agent, recent_hits)
    location = lookup_location(client_ip)
    now_iso = datetime.now().isoformat()

    save_event(
        token_id=token_id,
        triggered_at=now_iso,
        ip_address=client_ip,
        request_method=request.method,
        user_agent=user_agent,
        alert_type="HONEY_TOKEN_TRIGGERED",
        severity=risk_data["severity"],
        message=f"Honeytoken accessed [Score: {risk_data['risk_score']}]",
        location=location,
        risk_score=risk_data["risk_score"],
    )

    event_payload = {
        "token_id": token_id,
        "triggered_at": now_iso,
        "ip_address": client_ip,
        "request_method": request.method,
        "user_agent": user_agent,
        "status": "TRIGGERED",
        "risk_score": risk_data["risk_score"],
        "severity": risk_data["severity"],
        "resource_name": asset_name,
        "location": location,
    }
    generate_alert(event_payload, risk_score=risk_data["risk_score"], severity=risk_data["severity"])
    broadcast_sse_event(event_payload)

    return jsonify({
        "message": "Honey Token Triggered",
        "event": event_payload,
        "risk_score": risk_data["risk_score"],
        "severity": risk_data["severity"],
        "location": location,
    })


@app.route("/user/file/<token_id>")
def user_open_file(token_id):
    """User resource opening portal."""
    tokens = load_tokens()
    token = next((x for x in tokens if x.get("token_id") == token_id and x.get("token_type") == "FILE"), None)
    if not token:
        abort(404)

    client_ip = get_client_ip()
    if is_ip_blocked(client_ip):
        return render_template("file_accessed.html", filename=token.get("filename", "Protected File"), blocked=True)

    # Trigger token through the beacon logic
    beacon_listener(token_id)
    return render_template("file_accessed.html", filename=token.get("filename", "Protected File"), blocked=False)


# ============================================================================
# Honeypot Cloud Auth Gateway
# ============================================================================

@app.route("/api/v1/auth/verify", methods=["POST"])
def auth_verify():
    """
    Honeypot Cloud Auth Gateway:
    Emulates an internal OAuth/IAM validation endpoint.
    Extracts Bearer token or API key probe, scores risk with base weight 45.0,
    records incident, and returns realistic 401 Unauthorized with WWW-Authenticate header.
    """
    client_ip = get_client_ip()
    if is_ip_blocked(client_ip):
        return jsonify({"status": "error", "message": "Access blocked by administrator"}), 403

    user_agent = request.headers.get("User-Agent", "Unknown")
    auth_header = request.headers.get("Authorization", "")
    body_json = request.get_json(silent=True) or {}

    probe_credential = auth_header or body_json.get("token") or body_json.get("api_key") or "probe_unknown"
    token_id = f"AUTH-PROBE-{secrets.token_hex(4).upper()}"

    # Compute risk score with asset weight 45.0 (Cloud API Key Probe)
    recent_hits = get_recent_hit_count(client_ip, minutes=5) + 1
    risk_data = calculate_risk_score(
        asset_name="aws_prod_credentials.env",
        user_agent=user_agent,
        recent_hits=recent_hits,
    )

    now_iso = datetime.now().isoformat()
    location = lookup_location(client_ip)

    save_event(
        token_id=token_id,
        triggered_at=now_iso,
        ip_address=client_ip,
        request_method=request.method,
        user_agent=user_agent,
        alert_type="HONEYPOT_CREDENTIAL_PROBE",
        severity=risk_data["severity"],
        message=f"Unauthorized Cloud API Key probe detected: {str(probe_credential)[:40]}...",
        location=location,
        risk_score=risk_data["risk_score"],
    )

    event_payload = {
        "token_id": token_id,
        "triggered_at": now_iso,
        "ip_address": client_ip,
        "request_method": "POST",
        "user_agent": user_agent,
        "status": "TRIGGERED",
        "risk_score": risk_data["risk_score"],
        "severity": risk_data["severity"],
        "resource_name": "Decoy Cloud IAM Gateway",
        "location": location,
    }
    generate_alert(event_payload, risk_score=risk_data["risk_score"], severity=risk_data["severity"])
    broadcast_sse_event(event_payload)

    response_payload = {
        "status": "error",
        "data": None,
        "error": "The provided credentials are invalid, revoked, or lack necessary IAM privileges.",
    }
    resp = jsonify(response_payload)
    resp.status_code = 401
    resp.headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
    return resp


# ============================================================================
# Real-Time SSE Alert Streaming
# ============================================================================

@app.route("/api/v1/stream/alerts", methods=["GET"])
def stream_alerts():
    """
    Server-Sent Events (SSE) endpoint:
    Streams live incident alerts directly to connected SOC dashboards.
    """
    def event_stream():
        client_queue = queue.Queue(maxsize=50)
        with _sse_lock:
            _sse_subscribers.append(client_queue)
        try:
            # Yield initial connection confirmation
            yield f": connected to CyberGuard SOC alert stream\n\n"
            while True:
                try:
                    event = client_queue.get(timeout=20.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except queue.Empty:
                    # Keep-alive comment
                    yield f": keepalive\n\n"
        finally:
            with _sse_lock:
                if client_queue in _sse_subscribers:
                    _sse_subscribers.remove(client_queue)

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ============================================================================
# SOC Admin & Investigation API Endpoints
# ============================================================================

@app.route("/api/dashboard-data")
@admin_required
def dashboard_data():
    return jsonify(build_dashboard_payload())


@app.route("/api/block-ip", methods=["POST"])
@admin_required
def api_block_ip():
    ip = str((request.get_json(silent=True) or {}).get("ip_address", "")).strip()
    if not ip:
        return jsonify({"success": False, "message": "IP address is required."}), 400
    block_ip(ip, datetime.now().isoformat())
    return jsonify({"success": True, "message": f"IP {ip} has been blocked.", "ip_address": ip})


@app.route("/api/unblock-ip", methods=["POST"])
@admin_required
def api_unblock_ip():
    ip = str((request.get_json(silent=True) or {}).get("ip_address", "")).strip()
    if not ip:
        return jsonify({"success": False, "message": "IP address is required."}), 400
    unblock_ip(ip)
    return jsonify({"success": True, "message": f"IP {ip} has been unblocked.", "ip_address": ip})


@app.route("/dashboard")
@admin_required
def dashboard():
    return render_template(
        "dashboard.html",
        admin_username=session.get("admin_username", "admin"),
        server_ip=system_lan_ip(),
    )


@app.route("/health")
def health():
    return jsonify({"status": "online", "system": "CyberGuard SOC", "server_ip": system_lan_ip()})


if __name__ == "__main__":
    lan = system_lan_ip()
    print("\n=======================================================")
    print("🛡️  CYBERGUARD SOC: HONEYTOKEN-BASED INSIDER THREAT DETECTOR")
    print("=======================================================")
    print(f"Local Console: http://127.0.0.1:5000")
    print(f"LAN Gateway:   http://{lan}:5000")
    print("Admin Portal:  /admin/login")
    print("User Portal:   /user-dashboard")
    print("=======================================================\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
