import azure.functions as func
import json
import logging
import os
import requests
import datetime
import hmac
import hashlib
import base64

def post_to_log_analytics(workspace_id: str, shared_key: str, body: str, log_type: str) -> int:
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)
    string_to_hash = f"{method}\n{content_length}\n{content_type}\nx-ms-date:{rfc1123date}\n{resource}"
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode("utf-8")
    authorization = f"SharedKey {workspace_id}:{encoded_hash}"
    uri = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    headers = {
        "content-type": content_type,
        "Authorization": authorization,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date
    }
    response = requests.post(uri, data=body, headers=headers)
    return response.status_code

def main(msg: func.ServiceBusMessage) -> None:
    body = msg.get_body().decode("utf-8")
    logging.info(f"Analysis result received: {body[:200]}")

    try:
        result = json.loads(body)
    except json.JSONDecodeError:
        logging.error("Invalid JSON in analysis-queue message")
        return

    workspace_id = os.environ.get("LOG_ANALYTICS_WORKSPACE_ID", "")
    shared_key = os.environ.get("LOG_ANALYTICS_SHARED_KEY", "")

    if workspace_id and shared_key:
        status = post_to_log_analytics(workspace_id, shared_key, body, "VolatilityAnalysis")
        logging.info(f"Posted to Log Analytics — HTTP {status}")
    else:
        logging.warning("LOG_ANALYTICS_WORKSPACE_ID or LOG_ANALYTICS_SHARED_KEY not set — skipping LA post")

    risk = result.get("riskLevel", "UNKNOWN")
    if risk in ("HIGH", "CRITICAL"):
        logging.warning(f"HIGH RISK INDICATOR DETECTED: {result.get('indicator', 'unknown')} on {result.get('blobName', 'unknown')}")
