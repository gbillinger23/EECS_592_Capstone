
import json
import os
import uuid
from datetime import datetime, timezone

import boto3

s3 = boto3.client("s3")

BUCKET = os.environ.get("LOG_BUCKET", "metadatapackets--use2-az1--x-s3")


def _parse_timestamp(ts: str) -> datetime:
    """
    Supports:
      - ISO 8601: 2026-02-28T03:10:20Z
      - Project format: DD/MM/YYYY -- HH:MM:SS
    Falls back to current UTC time if invalid/missing.
    """
    if not ts or not isinstance(ts, str):
        return datetime.now(timezone.utc)

    # ISO 8601 (Zulu)
    try:
        if "T" in ts and ts.endswith("Z"):
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        pass

    # Project format
    try:
        return datetime.strptime(ts, "%d/%m/%Y -- %H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _extract_payload(event):

    body = event.get("body", event)

    if isinstance(body, str):
        try:
            return json.loads(body)
        except Exception:
            return {"raw_body": body}

    if isinstance(body, dict):
        return body

    return {"raw_body": str(body)}


def lambda_handler(event, context):
    data = _extract_payload(event)

    # Normalize timestamp for indexing + partitions
    ts = _parse_timestamp(data.get("timestamp"))
    iso_ts = ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Required index fields
    severity = str(data.get("severity", "INFO")).upper()
    rule_id = str(data.get("rule_id", "NONE")).upper()
    event_type = str(data.get("event_type", "metadata")).lower()

    # Store normalized fields + original payload
    record = {
        "timestamp": iso_ts,
        "severity": severity,
        "rule_id": rule_id,
        "event_type": event_type,
        "original": data
    }

    # Partitioned S3 key schema
    key = (
        "ingested/logs/"
        f"year={ts:%Y}/month={ts:%m}/day={ts:%d}/hour={ts:%H}/"
        f"rule_id={rule_id}/severity={severity}/"
        f"{uuid.uuid4().hex}.json"
    )

    # Write to S3 with encryption at rest
    s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=json.dumps(record).encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="AES256"
    )

    return {
        "statusCode": 200,
        "body": json.dumps({"ok": True, "s3_key": key})
    }