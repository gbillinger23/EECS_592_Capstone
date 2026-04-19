"""
s3_archive_service.py
=====================
S3 archive service for long-term audit log retention.

Archive strategy
----------------
- Primary storage : DynamoDB AuditLogs (90-day TTL via expiresAt field)
- Archive         : S3  audit-logs-archive/  (triggered when logs are > 30 days old)
- S3 path format  : audit-logs-archive/{YYYY}/{MM}/{DD}/{userId}-{logId}.json
- Encryption      : AES256 (server-side)

In production this archival job would be triggered by:
  - An AWS Lambda on a CloudWatch Events / EventBridge schedule (daily cron)
  - OR an AWS Step Functions workflow

For now, ``archive_old_logs`` is a stub that documents the pattern.
``archive_log_to_s3`` is a fully functional single-item uploader.

Required environment variable
------------------------------
ARCHIVE_BUCKET  – S3 bucket name (default: audit-logs-archive)
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger(__name__)

ARCHIVE_BUCKET = os.environ.get("ARCHIVE_BUCKET", "audit-logs-archive")
AWS_REGION     = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "us-east-2")

_s3_client = None


def _get_s3():
    """Return a (cached) boto3 S3 client."""
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3", region_name=AWS_REGION)
    return _s3_client


def archive_log_to_s3(log_entry: dict) -> str:
    """
    Archive a single audit log entry to S3.

    Path format: audit-logs-archive/{YYYY}/{MM}/{DD}/{userId}-{logId}.json

    Parameters
    ----------
    log_entry : dict – Audit log item from DynamoDB (must contain
                       'timestamp', 'userId', and 'logId' keys)

    Returns
    -------
    str – The S3 object key where the log was stored.

    Raises
    ------
    KeyError      – If log_entry is missing required fields.
    RuntimeError  – On S3 upload failure.
    """
    ts    = datetime.fromisoformat(log_entry["timestamp"])
    year  = ts.strftime("%Y")
    month = ts.strftime("%m")
    day   = ts.strftime("%d")
    key   = (
        f"audit-logs-archive/{year}/{month}/{day}/"
        f"{log_entry['userId']}-{log_entry['logId']}.json"
    )

    try:
        _get_s3().put_object(
            Bucket=ARCHIVE_BUCKET,
            Key=key,
            Body=json.dumps(log_entry, default=str),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        logger.info(
            "[s3Archive] Archived log %s → s3://%s/%s",
            log_entry["logId"], ARCHIVE_BUCKET, key,
        )
        return key
    except (ClientError, BotoCoreError) as exc:
        logger.error("[s3Archive] S3 upload failed for log %s: %s", log_entry.get("logId"), exc)
        raise RuntimeError("S3 archive upload failed") from exc


def archive_old_logs(dynamodb_service=None) -> dict:
    """
    Stub for the scheduled archival job that moves logs older than 30 days
    from DynamoDB to S3 and deletes them from DynamoDB.

    In production this function body would:
      1. Scan DynamoDB AuditLogs for items where timestamp < (now - 30 days)
      2. Call archive_log_to_s3() for each matching item
      3. Delete the item from DynamoDB after successful S3 write
      4. Publish CloudWatch metrics for archive count / errors

    Parameters
    ----------
    dynamodb_service : module – Optional; the dynamodb_service module for
                                running the scan (not needed for the stub).

    Returns
    -------
    dict – Status payload describing what *would* happen in production.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    logger.info("[s3Archive] archive_old_logs() called — stub implementation")
    logger.info("[s3Archive] Would archive logs older than %s", cutoff.isoformat())
    logger.info(
        "[s3Archive] Production flow: "
        "Scan DynamoDB → archive_log_to_s3() → DeleteItem from DynamoDB"
    )

    return {
        "status":      "stub — not yet deployed as a Lambda",
        "cutoffDate":  cutoff.isoformat(),
        "targetBucket": ARCHIVE_BUCKET,
        "pathFormat":  "audit-logs-archive/{YYYY}/{MM}/{DD}/{userId}-{logId}.json",
        "description": (
            "In production, a CloudWatch-scheduled Lambda would invoke this "
            "function daily to archive logs older than 30 days and free up "
            "DynamoDB capacity before the 90-day TTL evicts them."
        ),
    }
