import os
from dotenv import load_dotenv
import requests
import json
import urllib3
from base64 import b64encode
import pymongo
import schedule
import time
from datetime import datetime, timezone

load_dotenv("./.env")

# --- Configuration ---
MONGO_URI = os.getenv("MONGO_URI")
WAZUH_API_URL = os.getenv("WAZUH_API_URL")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASS = os.getenv("WAZUH_PASS")

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- MongoDB Atlas Configuration ---
client = pymongo.MongoClient(MONGO_URI)
db = client["wazuh_logs"]
collection = db["agent_events"]

# --- Wazuh API Configuration ---
VERIFY_SSL = False  # True if using valid certs
TIMEOUT = 10

# --- Get Token ---
def get_token():
    try:
        login_url = f"{WAZUH_API_URL}/security/user/authenticate"
        basic_auth = f"{WAZUH_USER}:{WAZUH_PASS}".encode()
        login_headers={
            "Content-Type": "application/json",
            "Authorization": f'Basic {b64encode(basic_auth).decode()}'
            }
        response = requests.post(login_url, headers=login_headers, verify=False)
        # response.raise_for_status()
        print("authenticated ", response.json()['data']['token'])
        return response.json()['data']['token']
    except requests.exceptions.RequestException as e:
        print(f"❌ Error getting token: {e}")
        return None

# --- Fetch Logs from Wazuh ---
def fetch_logs(token):
    try:
        headers = {
            "Content-Type": 'application/json',
            "Authorization": f"Bearer {token}"
            }
        response = requests.get(
            f"{WAZUH_API_URL}/agents",
            headers=headers,
            verify=VERIFY_SSL,
            timeout=TIMEOUT
        )
        response.raise_for_status()
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        return response.json().get("data", {}).get("affected_items", [])
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching logs: {e}")
        return []

# --- Save Logs to MongoDB ---
def save_logs_to_mongo(logs):
    if logs:
        for log in logs:
            log["_fetched_at"] = datetime.now(timezone.utc)
        result = collection.insert_many(logs)
        print(f"✅ {len(result.inserted_ids)} logs saved to MongoDB at {datetime.now(timezone.utc)}.")
    else:
        print("ℹ️ No logs to save.")

# --- Complete Workflow ---
def run():
    print(f"\n🔄 Running Wazuh log fetch at {datetime.now(timezone.utc)}")
    token = get_token()
    if token:
        logs = fetch_logs(token)
        save_logs_to_mongo(logs)

# --- Schedule Every 15 Minutes ---
schedule.every(15).minutes.do(run)

# Run once at start
run()

print("🕒 Scheduler started. Fetching logs every 15 minutes... (Press Ctrl+C to stop)")
while True:
    schedule.run_pending()
    time.sleep(1)