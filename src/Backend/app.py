'''
NetGuard Core API Server (app.py)
================================
FIX NOTES (2026-03-25):
  1. packet_worker thread is now actually STARTED (was missing the thread launch call)
  2. packet_worker no longer calls forward_metadata (that belongs in Metadata_extraction.py standalone mode)
  3. Interface auto-detection improved
  4. Added /api/debug endpoint to diagnose capture issues
  5. Rules path resolved relative to app.py (not CWD) so run.sh from project root works
  6. database.py now uses check_same_thread=False + Lock (fixes SQLite ProgrammingError)
'''

import threading
import os
import json
import datetime
import time

# Rules live in src/rules/ — one level UP from src/Backend/ where app.py lives.
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_DIR    = os.path.join(_BACKEND_DIR, "rules")

from flask import Flask, jsonify, request
from flask_cors import CORS

from database import PacketDatabase
import capture_packet
from Metadata_extraction import extract_metadata
from forward_to_cloud import forward_metadata
from rules_parser import load_rules

import boto3
from botocore.exceptions import BotoCoreError, ClientError

app = Flask(__name__)
CORS(app)

db = PacketDatabase()

AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-2")
LOG_BUCKET = os.environ.get("LOG_BUCKET", "monitoring-pcap-storage")

# Skip upfront connectivity check — IAM denies ListBuckets and HeadBucket.
# Just build the client; individual S3 calls will succeed or fail gracefully.
_has_creds = bool(os.environ.get("AWS_ACCESS_KEY_ID"))
try:
    s3_client     = boto3.client("s3", region_name=AWS_REGION)
    AWS_AVAILABLE = _has_creds
    status = "✅ LIVE" if AWS_AVAILABLE else "⚠️  no credentials"
    print(f"AWS S3 client ready: s3://{LOG_BUCKET} ({AWS_REGION}) — {status}")
except Exception as e:
    s3_client     = None
    AWS_AVAILABLE = False
    print(f"⚠️  AWS client init failed: {e}")

event_log  = []
event_lock = threading.Lock()

s3_cache = []
s3_cache_time = 0

# ── Packet counter for debug ─────────────────────────────────────────────────
packets_processed = 0
packets_processed_lock = threading.Lock()


def evaluate_rules_local(metadata):
    try:
        rules = load_rules(RULES_DIR)
    except Exception as e:
        print(f"[RULES] Failed to load rules: {e}")
        return

    for rule in rules:
        matched = True
        for cond in rule.conditions:
            field, op, value = cond.get("field"), cond.get("operator"), cond.get("value")
            actual = metadata.get(field)
            if actual is None:
                matched = False; break
            if op in ("eq",  "==")  and str(actual) != str(value):
                matched = False; break
            if op in ("neq", "!=")  and str(actual) == str(value):
                matched = False; break
            if op == "gt":
                try:
                    if not (float(actual) > float(value)):
                        matched = False; break
                except (TypeError, ValueError):
                    matched = False; break
            if op == "lt":
                try:
                    if not (float(actual) < float(value)):
                        matched = False; break
                except (TypeError, ValueError):
                    matched = False; break
            if op == "contains" and str(value).lower() not in str(actual).lower():
                matched = False; break

        if matched:
            with event_lock:
                event_log.append({
                    "rule_id":     rule.id,
                    "description": rule.description,
                    "severity":    rule.severity,
                    "metadata":    metadata.copy(),
                    "timestamp":   metadata.get("timestamp", ""),
                    "tags":        rule.tags or [],
                    "source":      "local"
                })
                if len(event_log) > 500:
                    event_log.pop(0)


def packet_worker():
    """
    Daemon thread: pulls packets from the capture queue,
    extracts metadata, stores to SQLite, evaluates rules.
    Forwarding throttled — every 10th packet sent to API Gateway → Lambda → S3.
    """
    global packets_processed
    thread_db = PacketDatabase()
    print("[WORKER] Packet worker thread started ✅")

    while True:
        try:
            pkt  = capture_packet.packets.get()
            meta = extract_metadata(pkt)

            if meta:
                thread_db.insert_metadata(meta)
                evaluate_rules_local(meta)

                with packets_processed_lock:
                    packets_processed += 1

                # Forward every 10th packet to AWS (throttle to avoid saturating API Gateway)
                if packets_processed % 10 == 0:
                    try:
                        forward_metadata(meta)
                    except Exception as fe:
                        print(f"[WORKER] Forward error: {fe}")

                if packets_processed % 50 == 0:
                    print(f"[WORKER] Processed {packets_processed} packets so far...")
        except Exception as e:
            print(f"[WORKER] Error processing packet: {e}")


# ── START THE PACKET WORKER THREAD ──────────────────────────────────────────
# THIS WAS THE MISSING PIECE — thread must be created AND started
_worker_thread = threading.Thread(target=packet_worker, daemon=True)
_worker_thread.start()
print(f"[STARTUP] Packet worker thread launched (alive={_worker_thread.is_alive()})")


# ════════════════════════════ API ROUTES ═════════════════════════════════════

@app.route("/api/packets")
def api_packets():
    rows = db.get_all_packets()
    result = [
        {
            "id":       r[0],
            "timestamp": r[1],
            "src_ip":   r[2],
            "dst_ip":   r[3],
            "src_port": r[4],
            "dst_port": r[5],
            "protocol": r[6]
        }
        for r in rows
    ]
    return jsonify(list(reversed(result[-500:])))

@app.route("/api/logs/search/local")
def api_logs_search_local():
    """
    Search locally ingested packet metadata stored in SQLite.
    """
    # Read filters
    src_ip   = request.args.get("src_ip")
    dst_ip   = request.args.get("dst_ip")
    protocol = request.args.get("protocol")
    src_port = request.args.get("src_port")
    dst_port = request.args.get("dst_port")
    time_win = request.args.get("time")

    rows = db.get_all_packets()

    # Convert rows into dicts
    records = [
        {
            "id":       r[0],
            "timestamp": r[1],
            "src_ip":   r[2],
            "dst_ip":   r[3],
            "src_port": r[4],
            "dst_port": r[5],
            "protocol": r[6]
        }
        for r in rows
    ]

    # Apply filters
    def match(rec):
        if src_ip and rec["src_ip"] != src_ip:
            return False
        if dst_ip and rec["dst_ip"] != dst_ip:
            return False
        if protocol and rec["protocol"] != protocol:
            return False
        if src_port and str(rec["src_port"]) != src_port:
            return False
        if dst_port and str(rec["dst_port"]) != dst_port:
            return False

        # Time window filter
        if time_win:
            try:
                ts = datetime.datetime.fromisoformat(rec["timestamp"])
                now = datetime.datetime.utcnow()
                delta = (now - ts).total_seconds()

                if time_win == "5m"  and delta > 300:   return False
                if time_win == "15m" and delta > 900:   return False
                if time_win == "1h"  and delta > 3600:  return False
                if time_win == "24h" and delta > 86400: return False
            except Exception:
                return False

        return True

    filtered = [r for r in records if match(r)]
    return jsonify(filtered)

@app.route("/api/stats")
def api_stats():
    from collections import Counter
    rows  = db.get_all_packets()
    total = len(rows)
    tcp   = sum(1 for r in rows if r[6] == "TCP")
    udp   = sum(1 for r in rows if r[6] == "UDP")
    other = total - tcp - udp

    dst_ports = Counter(r[5] for r in rows if r[5])
    src_ips   = Counter(r[2] for r in rows if r[2])

    return jsonify({
        "total":         total,
        "tcp":           tcp,
        "udp":           udp,
        "other":         other,
        "unique_src":    len(set(r[2] for r in rows if r[2])),
        "top_ports":     [{"port": p, "count": c} for p, c in dst_ports.most_common(5)],
        "top_ips":       [{"ip": ip, "count": c}  for ip,  c in src_ips.most_common(5)],
        "local_events":  len(event_log),
        "aws_available": AWS_AVAILABLE,
    })


@app.route("/api/events/local")
def api_events_local():
    with event_lock:
        return jsonify(list(reversed(event_log[-200:])))


@app.route("/api/rules")
def api_rules():
    try:
        rules = load_rules(RULES_DIR)
        return jsonify([{
            "id": r.id, "description": r.description,
            "severity": r.severity, "conditions": r.conditions,
            "window": r.window, "tags": r.tags
        } for r in rules])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/debug")
def api_debug():
    """Diagnostic endpoint — check capture queue and worker status."""
    return jsonify({
        "worker_alive":       _worker_thread.is_alive(),
        "packets_processed":  packets_processed,
        "queue_size":         capture_packet.packets.qsize(),
        "capture_interface":  capture_packet.INTERFACE,
        "db_total":           len(db.get_all_packets()),
        "event_log_size":     len(event_log),
        "aws_available":      AWS_AVAILABLE,
    })

@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    data = request.json or {}
    packet_id = data.get("packet_id")
    rule_id   = data.get("rule_id")
    feedback  = data.get("feedback")
    note      = data.get("note", "")

    if not feedback:
        return jsonify({"error": "feedback required"}), 400

    ts = datetime.datetime.utcnow().isoformat()

    db.insert_feedback(packet_id, rule_id, feedback, note, ts)

    return jsonify({"status": "ok"})

@app.route("/api/feedback", methods=["GET"])
def api_feedback_get():
    rows = db.get_all_feedback()
    return jsonify([
        {
            "id": r[0],
            "packet_id": r[1],
            "rule_id": r[2],
            "feedback": r[3],
            "note": r[4],
            "timestamp": r[5]
        }
        for r in rows
    ])


# ══ AWS ROUTES ════════════════════════════════════════════════════════════════

def _s3_list_keys(prefix, max_keys=200):
    if not AWS_AVAILABLE:
        return []
    try:
        resp = s3_client.list_objects_v2(
            Bucket=LOG_BUCKET,
            Prefix=prefix,
            MaxKeys=max_keys
        )
        return [o["Key"] for o in resp.get("Contents", [])]
    except (BotoCoreError, ClientError) as e:
        print(f"[S3] list_objects_v2 failed: {e}")
        return []

def _s3_read_json(key):
    try:
        obj = s3_client.get_object(Bucket=LOG_BUCKET, Key=key)
        return json.loads(obj["Body"].read().decode("utf-8"))
    except Exception as e:
        print(f"[S3] read failed: {e}")
        return None

@app.route("/api/aws/alerts")
def api_aws_alerts():
    keys   = _s3_list_keys("alerts/", max_keys=100)
    alerts = []
    for key in sorted(keys, reverse=True)[:100]:
        data = _s3_read_json(key)
        if data:
            data["_s3_key"] = key
            alerts.append(data)
    return jsonify(alerts)


@app.route("/api/aws/ingested")
def api_aws_ingested():
    keys    = _s3_list_keys("ingested/logs/", max_keys=200)
    records = []
    for key in sorted(keys, reverse=True)[:200]:
        data = _s3_read_json(key)
        if data:
            data["_s3_key"] = key
            records.append(data)
    return jsonify(records)

@app.route("/api/aws/stats")
def api_aws_stats():
    alert_keys    = _s3_list_keys("alerts/",        max_keys=500)
    ingested_keys = _s3_list_keys("ingested/logs/", max_keys=500)

    sev_counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    rule_counts = {}

    for key in sorted(alert_keys, reverse=True)[:100]:
        data = _s3_read_json(key)
        if not data:
            continue
        sev = str(data.get("severity", "INFO")).upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        rule = data.get("rule", "unknown")
        rule_counts[rule] = rule_counts.get(rule, 0) + 1

    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return jsonify({
        "total_alerts":   len(alert_keys),
        "total_ingested": len(ingested_keys),
        "severity":       sev_counts,
        "top_rules":      [{"rule": r, "count": c} for r, c in top_rules],
    })


if __name__ == "__main__":
    print("═" * 60)
    print("🚀 NetGuard API Server v1.1 (fixed)")
    print(f"📡 Local:    http://localhost:5000")
    print(f"📊 Debug:    http://localhost:5000/api/debug")
    print(f"☁️  AWS:     s3://{LOG_BUCKET} ({AWS_REGION}) {'✅ LIVE' if AWS_AVAILABLE else '⚠️  LOCAL-ONLY'}")
    print("═" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
