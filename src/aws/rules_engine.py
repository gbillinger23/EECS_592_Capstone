# THIS IS A RECREATION OF THE LAMBDA CODE LOCATED ON AWS

# THIS CODE IS REACTIVE UPON PACKET LOGS ENTERING THE S3 BUCKET.
# THEN RULE EVALUATION IS PERFORMED ON THEM AND ALERTS ARE GENERATED.

#!/usr/bin/env python3
import json
import datetime
import time
from decimal import Decimal
import boto3
from boto3.dynamodb.conditions import Key
import logging
import yaml
from collections import defaultdict
from urllib.parse import unquote_plus

# ───────────────────────── CONFIG ─────────────────────────
S3_BUCKET      = "monitoring-pcap-storage"
RULES_PREFIX   = "rules/"
ALERTS_PREFIX  = "alerts/"

dynamodb = boto3.resource("dynamodb")
TABLE = dynamodb.Table("net_detection_state")

WHITELIST_IPS = {
    "169.254.169.254",
    "127.0.0.1",
}

ALERT_COOLDOWN_SECONDS = 30

log = logging.getLogger()
log.setLevel(logging.INFO)

s3 = boto3.client("s3")

# ─────────────────────── RULE LOADER ──────────────────────

def load_rules_from_s3():
    rules = []

    resp = s3.list_objects_v2(
        Bucket=S3_BUCKET,
        Prefix=RULES_PREFIX
    )

    if "Contents" not in resp:
        log.warning("[RULES] No rule files found in S3.")
        return rules

    for obj in resp["Contents"]:
        key = obj["Key"]
        if not key.endswith(".yaml") and not key.endswith(".yml"):
            continue

        log.info(f"[RULES] Loading rule file: {key}")

        file_obj = s3.get_object(Bucket=S3_BUCKET, Key=key)
        content = file_obj["Body"].read().decode("utf-8")
        data = yaml.safe_load(content)

        # Your rule files contain ONE rule, with "id:" not "name:"
        if isinstance(data, dict) and "id" in data:
            rule = data.copy()
            rule["name"] = rule.pop("id")
            rules.append(rule)
            continue

        # If a file contains multiple rules (future-proof)
        if isinstance(data, dict) and "rules" in data:
            for r in data["rules"]:
                if "id" in r:
                    r["name"] = r.pop("id")
                rules.append(r)

    log.info(f"[RULES] Loaded {len(rules)} total rules from S3.")
    return rules

RULES = load_rules_from_s3()

# ─────────────────────── STATE TRACKER ─────────────────────

class RuleTracker:
    def __init__(self):
        pass

    def _put_event(self, pk, sk, ttl_seconds):
        now = int(time.time())
        ttl = now + ttl_seconds

        TABLE.put_item(
            Item={
                "pk": pk,
                "sk": sk,
                "ttl": ttl
            }
        )

    def record(self, rule_name, src_ip, metadata=None):
        ts = int(time.time())
        pk = f"{rule_name}#{src_ip}"
        sk = f"{ts}#{metadata}" if metadata else str(ts)

        # All packet events expire after 60 seconds
        self._put_event(pk, sk, ttl_seconds=60)

    def _query_recent(self, pk, window_seconds):
        cutoff = int(time.time()) - window_seconds

        resp = TABLE.query(
            KeyConditionExpression=Key("pk").eq(pk)
        )

        items = resp.get("Items", [])
        return [
            item for item in items
            if int(item["sk"].split("#")[0]) >= cutoff
        ]

    def count_in_window(self, rule_name, src_ip, window_seconds):
        pk = f"{rule_name}#{src_ip}"
        items = self._query_recent(pk, window_seconds)
        return len(items)

    def distinct_values_in_window(self, rule_name, src_ip, window_seconds):
        pk = f"{rule_name}#{src_ip}"
        items = self._query_recent(pk, window_seconds)

        values = set()
        for item in items:
            parts = item["sk"].split("#")
            if len(parts) > 1:
                values.add(parts[1])
        return values

    def is_on_cooldown(self, rule_name, src_ip, cooldown_seconds):
        pk = f"cooldown#{rule_name}#{src_ip}"
        resp = TABLE.get_item(Key={"pk": pk, "sk": "state"})

        if "Item" not in resp:
            return False

        last = resp["Item"]["timestamp"]
        return (time.time() - last) < cooldown_seconds

    def mark_alerted(self, rule_name, src_ip):
        now = int(time.time())
        ttl = now + 300  # cooldown entries expire after 5 minutes

        pk = f"cooldown#{rule_name}#{src_ip}"

        TABLE.put_item(
            Item={
                "pk": pk,
                "sk": "state",
                "timestamp": now,
                "ttl": ttl
            }
        )

# ─────────────────────── PACKET PARSER ─────────────────────

def parse_packet(packet):
    original = packet.get("original")
    if not original:
        return None

    return {
        "protocol": "tcp",
        "src_ip": original.get("src_ip"),
        "dst_ip": original.get("dst_ip"),
        "dst_port": str(original.get("dst_port")),
        "tcp_flags": None,
        "icmp_type": None,
    }

# ─────────────────────── RULE EVALUATOR ─────────────────────

def evaluate_rules(packet_info, rules, tracker):
    alerts = []

    src_ip    = packet_info.get("src_ip")
    dst_ip    = packet_info.get("dst_ip")
    dst_port  = packet_info.get("dst_port")

    if not src_ip or src_ip in WHITELIST_IPS:
        return alerts

    # Derived fields needed by your rules
    tracker.record("unique_dst_ports", src_ip, metadata=dst_port)
    tracker.record("unique_dst_ips", src_ip, metadata=dst_ip)
    tracker.record("connection_count", src_ip)

    packet_info["unique_dst_ports"] = tracker.distinct_values_in_window(
        "unique_dst_ports", src_ip, 60
    )
    packet_info["unique_dst_ips"] = tracker.distinct_values_in_window(
        "unique_dst_ips", src_ip, 60
    )
    packet_info["connection_count"] = tracker.count_in_window(
        "connection_count", src_ip, 60
    )

    for rule in rules:
        rule_name = rule["name"]
        severity  = rule.get("severity", "INFO")
        window    = rule.get("window", 60)

        triggered = False

        # Generic condition evaluator
        if "conditions" in rule:
            match = True

            for cond in rule["conditions"]:
                field = cond["field"]
                operator = cond["operator"]
                value = cond["value"]

                packet_value = packet_info.get(field)

                # Normalize types
                if isinstance(packet_value, set):
                    packet_value = len(packet_value)

                if operator == "in":
                    if str(packet_value) not in [str(v) for v in value]:
                        match = False

                elif operator == "==":
                    if str(packet_value) != str(value):
                        match = False

                elif operator == ">":
                    if packet_value is None:
                        match = False
                    else:
                        try:
                            if int(packet_value) <= int(value):
                                match = False
                        except (ValueError, TypeError):
                            match = False

                elif operator == "not_internal":
                    if value is True:
                        if packet_value.startswith(("10.", "192.168.", "172.16.")):
                            match = False

                if not match:
                    break

            if match:
                triggered = True

        if triggered:
            if tracker.is_on_cooldown(rule_name, src_ip, ALERT_COOLDOWN_SECONDS):
                continue

            tracker.mark_alerted(rule_name, src_ip)

            alert = {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "rule": rule_name,
                "severity": severity,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "description": rule.get("description", ""),
            }
            alerts.append(alert)

    return alerts

# ─────────────────────── ALERT UPLOADER ─────────────────────

def upload_single_alert(alert):
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    key = f"{ALERTS_PREFIX}{ts}-{alert['rule']}-{alert['src_ip']}.json"

    s3.put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=json.dumps(alert).encode("utf-8"),
        ContentType="application/json"
    )

    log.info(f"[ALERT] Uploaded {key}")

# ─────────────────────── MAIN HANDLER ─────────────────────

def lambda_handler(event, context):
    tracker = RuleTracker()

    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])

        log.info(f"[EVENT] Processing packet file: s3://{bucket}/{key}")

        obj = s3.get_object(Bucket=bucket, Key=key)
        raw = obj["Body"].read().decode("utf-8")

        try:
            packet_json = json.loads(raw)
        except json.JSONDecodeError:
            log.error("[ERROR] Invalid JSON packet")
            continue

        packet_info = parse_packet(packet_json)
        if not packet_info:
            continue

        alerts = evaluate_rules(packet_info, RULES, tracker)

        for alert in alerts:
            upload_single_alert(alert)

    return {"status": "ok"}
