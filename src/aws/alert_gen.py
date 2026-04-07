# NOT EXECUTABLE FROM GITHUB. RUN REMOTELY FROM AWS LAMBDA.
# THIS FUNCTION DETECTS WHEN ALERT IS GENERATED IN ALERTS/ ON AWS S3
# WHEN ALERT IS GENERATED, FORMAT AND SEND EMAIL DESCRIBING ALERT.

import json
import boto3
import urllib.parse
import os

s3 = boto3.client("s3")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ALERTS_BUCKET = os.environ["ALERTS_BUCKET"]
ALERTS_PREFIX = os.environ.get("ALERTS_PREFIX", "alerts/")

def lambda_handler(event, context):
    # Extract S3 info
    record = event["Records"][0]
    bucket = record["s3"]["bucket"]["name"]
    key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])

    # Only process alerts/ prefix
    if not key.startswith(ALERTS_PREFIX):
        return {"status": "ignored", "reason": "not in alerts prefix"}

    # Read alert JSON
    obj = s3.get_object(Bucket=bucket, Key=key)
    alert = json.loads(obj["Body"].read().decode("utf-8"))

    # Build email
    subject = f"ALERT: {alert.get('rule', 'Unknown Rule')} from {alert.get('src_ip', 'unknown')}"
    message = json.dumps(alert, indent=2)

    # Publish to SNS
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=message
    )

    return {
        "status": "sent",
        "alert_key": key
    }

