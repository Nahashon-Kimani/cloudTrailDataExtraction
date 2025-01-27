import json
import boto3

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    
    # Specify the S3 bucket and object key
    bucket_name = "aws-account-access-login-bkt"
    object_key = "events.json"
    
    # Read the JSON file from S3
    response = s3.get_object(Bucket=bucket_name, Key=object_key)
    json_content = response['Body'].read().decode('utf-8')
    data = json.loads(json_content)

    extracted_events = []
    
    # Iterate through all events
    for event in data.get("Events", []):
        event_id = event.get("EventId")
        event_time = event.get("EventTime")
        username = event.get("Username")  # Direct key lookup
        account_id = ""
        source_ip = ""
        console_login = ""
        mfa_used = ""
        
        if not username:
            # Extract from CloudTrailEvent if direct Username is missing
            cloudtrail_event_str = event.get("CloudTrailEvent", "{}")
            try:
                cloudtrail_event = json.loads(cloudtrail_event_str)  # Decode JSON string
            except json.JSONDecodeError:
                cloudtrail_event = {}

            user_identity = cloudtrail_event.get("userIdentity", {})
            username = user_identity.get("userName")  # Extract from userIdentity
            if not username:
                username = user_identity.get("arn", "N/A")  # Fallback to ARN if username is missing
            
            account_id = user_identity.get("accountId", "N/A")  # Account ID
            source_ip = cloudtrail_event.get("sourceIPAddress", "N/A")  # Source IP address
            console_login = cloudtrail_event.get("responseElements", {}).get("ConsoleLogin", "N/A")  # ConsoleLogin
            mfa_used = cloudtrail_event.get("additionalEventData", {}).get("MFAUsed", "N/A")  # MFAUsed
        
        else:
            account_id = event.get("accountId", "N/A")
            cloudtrail_event_str = event.get("CloudTrailEvent", "{}")
            try:
                cloudtrail_event = json.loads(cloudtrail_event_str)
            except json.JSONDecodeError:
                cloudtrail_event = {}

            source_ip = cloudtrail_event.get("sourceIPAddress", "N/A")
            console_login = cloudtrail_event.get("responseElements", {}).get("ConsoleLogin", "N/A")
            mfa_used = cloudtrail_event.get("additionalEventData", {}).get("MFAUsed", "N/A")

        extracted_events.append({
            "EventId": event_id,
            "EventTime": event_time,
            "Username": username,
            "accountId": account_id,
            "sourceIPAddress": source_ip,
            "ConsoleLogin": console_login,
            "MFAUsed": mfa_used
        })

    return extracted_events
