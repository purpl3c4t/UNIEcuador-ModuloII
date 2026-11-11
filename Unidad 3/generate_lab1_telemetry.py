import json
from datetime import datetime, timedelta

def create_event(time_offset_min, event_name, user_arn, ip, user_agent, error=None, request_params=None):
    base_time = datetime(2026, 11, 11, 3, 10, 0) + timedelta(minutes=time_offset_min)
    return {
        "eventTime": base_time.isoformat() + "Z",
        "eventName": event_name,
        "userIdentity": {
            "type": "AssumedRole" if "role" in user_arn.lower() else "IAMUser",
            "arn": user_arn
        },
        "sourceIPAddress": ip,
        "userAgent": user_agent,
        "errorCode": error,
        "requestParameters": request_params or {}
    }

events = [
    create_event(0, "DescribeInstances", "arn:aws:iam::123456789012:role/DevSecOpsInstanceRole", "10.0.1.5", "aws-sdk-go/v1.34.0"),
    create_event(1, "GetItem", "arn:aws:iam::123456789012:role/AppDynamoRole", "10.0.1.20", "aws-sdk-python/boto3"),
    create_event(2, "DescribeBuckets", "arn:aws:iam::123456789012:user/AliceAdmin", "192.0.2.45", "AWS-Console-Browser"),
    create_event(3, "ListFunctions", "arn:aws:iam::123456789012:user/AliceAdmin", "192.0.2.45", "AWS-Console-Browser"),
    create_event(10, "GetCallerIdentity", "arn:aws:iam::123456789012:role/DevSecOpsInstanceRole", "198.51.100.23", "aws-cli/2.15.0 Python/3.11"),
    create_event(11, "ListUsers", "arn:aws:iam::123456789012:role/DevSecOpsInstanceRole", "198.51.100.23", "aws-cli/2.15.0 Python/3.11", error="AccessDenied"),
    create_event(11, "ListRoles", "arn:aws:iam::123456789012:role/DevSecOpsInstanceRole", "198.51.100.23", "aws-cli/2.15.0 Python/3.11", error="AccessDenied"),
    create_event(12, "ListPolicies", "arn:aws:iam::123456789012:role/DevSecOpsInstanceRole", "198.51.100.23", "aws-cli/2.15.0 Python/3.11", error="AccessDenied"),
    create_event(14, "CreateFunction", "arn:aws:iam::123456789012:role/DevSecOpsInstanceRole", "198.51.100.23", "python-requests/2.31.0", request_params={"functionName": "BackdoorPrivEsc", "role": "arn:aws:iam::123456789012:role/AdministratorAccessRole"}),
    create_event(15, "RunInstances", "arn:aws:iam::123456789012:role/DevSecOpsInstanceRole", "198.51.100.23", "python-requests/2.31.0", request_params={"instanceType": "p3.8xlarge", "instanceId": "i-0cryptominer001"})
]

with open("audit_events.json", "w") as f:
    json.dump(events, f, indent=2)

print("[+] Archivo 'audit_events.json' generado exitosamente.")
