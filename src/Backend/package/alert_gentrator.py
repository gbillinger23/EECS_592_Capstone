"""
Author: Aryan Ghorpade
Date: 2/15/2026
Revision Date: 3/8/2026
Program Name: alert_gentrator.py

Program Description:    
Generates alert notifications for broken rules detected by rules_parser.py
and sends an email via AWS SNS topic subscription with the alert details.
"""
import boto3
import ipaddress
import rules_parser

SNS_TOPIC_ARN = 'arn:aws:sns:us-east-2:981743521769:sentinet_alert'

INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

def is_internal_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False

def evaluate_condition(condition, network_data):
    field    = condition["field"]
    operator = condition["operator"]
    value    = condition["value"]
    actual   = network_data.get(field)

    if actual is None:
        return False

    if operator == ">":
        return actual > value
    elif operator == "<":
        return actual < value
    elif operator == "==":
        return actual == value
    elif operator == ">=":
        return actual >= value
    elif operator == "<=":
        return actual <= value
    elif operator == "in":
        return actual in value
    elif operator == "not_internal":
        return not is_internal_ip(str(actual))
    elif operator == "internal":
        return is_internal_ip(str(actual))

    return False

def send_sns_notification(subject, message, topic_arn=SNS_TOPIC_ARN):
    sns_client = boto3.client('sns', region_name='us-east-2')
    response = sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=message
    )
    return response

def check_rules(network_data):
    rules = rules_parser.load_rules()
    for rule in rules:
        broken = all(evaluate_condition(c, network_data) for c in rule.conditions)
        if broken:
            subject = f"NETWORK ALERT [{rule.severity.upper()}] - Rule {rule.id}"
            message = (
                f"NETWORK ALERT\n"
                f"Rule ID: {rule.id}\n"
                f"Severity: {rule.severity.upper()}\n"
                f"Description: {rule.description}"
            )
            send_sns_notification(subject, message)