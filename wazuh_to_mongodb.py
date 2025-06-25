import os
import json
import time
import logging
import sys
import hashlib
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse
from base64 import b64encode
from dotenv import load_dotenv
import requests
import urllib3
import pymongo
import schedule
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Load environment variables from .env file
load_dotenv("./.env")

# --- Configuration ---
CONFIG = {
    "MONGO_URI": os.getenv("MONGO_URI"),
    "WAZUH_API_URL": os.getenv("WAZUH_API_URL"),
    "WAZUH_USER": os.getenv("WAZUH_USER"),
    "WAZUH_PASS": os.getenv("WAZUH_PASS"),
    "OPENSEARCH_URL": os.getenv("OPENSEARCH_URL"),
    "OPENSEARCH_USER": os.getenv("OPENSEARCH_USER", "admin"),
    "OPENSEARCH_PASS": os.getenv("OPENSEARCH_PASS", "admin"),
    "ENABLE_MONGODB_UPLOAD": True,
    "SAVE_TO_FILE": False,
    "MAX_SYSCHECK_PAGES": 100,
    "MAX_ALERT_PAGES": 100,
    "SCA_MAX_PAGES": 50,
    "OPENSEARCH_INDEX": "wazuh-alerts-4.x-*",
    "MAX_WORKERS": 5,  # For parallel agent processing
    "REQUEST_TIMEOUT": 30,
    "RETRY_STRATEGY": {
        "total": 3,
        "backoff_factor": 1,
        "status_forcelist": [429, 500, 502, 503, 504]
    }
}

# Disable insecure HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Create a requests session with retry capabilities
def create_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=CONFIG["RETRY_STRATEGY"]["total"],
        backoff_factor=CONFIG["RETRY_STRATEGY"]["backoff_factor"],
        status_forcelist=CONFIG["RETRY_STRATEGY"]["status_forcelist"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

# --- MongoDB Configuration ---
def init_mongodb():
    if not CONFIG["ENABLE_MONGODB_UPLOAD"]:
        logger.info("ℹ️ MongoDB upload is disabled via configuration")
        return None, None
    
    uri = CONFIG["MONGO_URI"]
    if not uri:
        logger.error("❌ MONGO_URI environment variable is not set")
        return None, None
    
    try:
        parsed = urlparse(uri)
        if not parsed.scheme.startswith("mongodb"):
            logger.error("❌ MONGO_URI must start with 'mongodb://' or 'mongodb+srv://'")
            return None, None
        
        # Mask credentials for logging
        masked_uri = uri
        if "@" in uri:
            user_part = uri.split("@")[0]
            masked_uri = uri.replace(user_part, "mongodb://****:****")
        logger.info(f"🔧 Using MONGO_URI: {masked_uri}")
        
        client = pymongo.MongoClient(uri)
        db = client["wazuh_config_assessment"]
        client.server_info()  # Test connection
        logger.info("✅ Successfully connected to MongoDB")
        return client, db
        
    except (ValueError, pymongo.errors.ConnectionFailure) as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        return None, None

# Initialize MongoDB
client, db = init_mongodb()

# --- Wazuh API Functions ---
def get_token(session):
    try:
        url = f"{CONFIG['WAZUH_API_URL']}/security/user/authenticate"
        basic_auth = f"{CONFIG['WAZUH_USER']}:{CONFIG['WAZUH_PASS']}".encode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {b64encode(basic_auth).decode()}"
        }
        
        response = session.post(url, headers=headers, verify=False, timeout=CONFIG["REQUEST_TIMEOUT"])
        response.raise_for_status()
        token = response.json()['data']['token']
        logger.info("✅ Authenticated with Wazuh API")
        return token
        
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Error getting authentication token: {e}")
        return None

def fetch_paginated_data(session, url, token, params=None):
    """Generic function to fetch paginated data from Wazuh API"""
    items = []
    offset = 0
    limit = 500
    page = 0
    total_items = 0
    
    headers = {"Authorization": f"Bearer {token}"}
    
    while True:
        try:
            # Update pagination parameters
            params = params or {}
            params.update({"offset": offset, "limit": limit})
            
            response = session.get(
                url,
                headers=headers,
                params=params,
                verify=False,
                timeout=CONFIG["REQUEST_TIMEOUT"]
            )
            response.raise_for_status()
            
            data = response.json().get("data", {})
            batch = data.get("affected_items", [])
            items.extend(batch)
            
            # Update total items on first page
            if page == 0:
                total_items = data.get("total_affected_items", 0)
            
            # Break conditions
            if len(batch) < limit or (total_items > 0 and offset + limit >= total_items):
                break
                
            offset += limit
            page += 1
            
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Error fetching data from {url}: {e}")
            break
            
    return items

def fetch_agents(session, token):
    logger.info("🔍 Fetching agents...")
    agents = fetch_paginated_data(session, f"{CONFIG['WAZUH_API_URL']}/agents", token)
    filtered_agents = [agent for agent in agents if agent["id"] != "000"]
    logger.info(f"📦 Fetched {len(filtered_agents)} active agents")
    return filtered_agents

def fetch_syscheck(session, token, agent_id):
    logger.info(f"🔍 Fetching syscheck for agent {agent_id}...")
    syscheck_logs = fetch_paginated_data(
        session, 
        f"{CONFIG['WAZUH_API_URL']}/syscheck/{agent_id}", 
        token
    )
    for log in syscheck_logs:
        log["agent_id"] = agent_id
    logger.info(f"📦 Fetched {len(syscheck_logs)} syscheck logs for agent {agent_id}")
    return syscheck_logs

def fetch_rules(session, token):
    logger.info("🔍 Fetching rules...")
    rules = fetch_paginated_data(session, f"{CONFIG['WAZUH_API_URL']}/rules", token)
    logger.info(f"📦 Fetched {len(rules)} detection rules")
    return rules

def fetch_sca(session, token, agent_id):
    """Fetch SCA policies with proper error handling"""
    logger.info(f"🔍 Fetching SCA policies for agent {agent_id}...")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        sca_url = f"{CONFIG['WAZUH_API_URL']}/sca/{agent_id}"
        
        # Fetch policy summaries
        response = session.get(sca_url, headers=headers, verify=False, timeout=CONFIG["REQUEST_TIMEOUT"])
        response.raise_for_status()
        data = response.json().get("data", {})
        summaries = data.get("affected_items", [])
        
        # Fetch policy details
        policies = []
        for summary in summaries:
            policy_id = summary.get("id")
            if not policy_id:
                continue
                
            policy_url = f"{CONFIG['WAZUH_API_URL']}/sca/{agent_id}/checks/{policy_id}"
            policy_response = session.get(policy_url, headers=headers, verify=False, timeout=CONFIG["REQUEST_TIMEOUT"])
            
            if policy_response.status_code == 200:
                policy_data = policy_response.json().get("data", {})
                policy_details = policy_data.get("affected_items", [])
                if policy_details:
                    merged = {**summary, **policy_details[0], "agent_id": agent_id}
                    policies.append(merged)
            else:
                logger.warning(f"⚠️ Failed to fetch SCA policy {policy_id} for agent {agent_id}: {policy_response.status_code}")
        
        logger.info(f"📦 Fetched {len(policies)} SCA policies for agent {agent_id}")
        return policies
        
    except Exception as e:
        logger.error(f"❌ Error fetching SCA for agent {agent_id}: {e}")
        return []

def fetch_software_inventory(session, token, agent_id):
    logger.info(f"🔍 Fetching software inventory for agent {agent_id}...")
    inventory = fetch_paginated_data(
        session,
        f"{CONFIG['WAZUH_API_URL']}/syscollector/{agent_id}/packages",
        token
    )
    for item in inventory:
        item["agent_id"] = agent_id
    logger.info(f"📦 Fetched {len(inventory)} software items for agent {agent_id}")
    return inventory

def fetch_os_info(session, token, agent_id):
    logger.info(f"🔍 Fetching OS info for agent {agent_id}...")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{CONFIG['WAZUH_API_URL']}/syscollector/{agent_id}/os"
        response = session.get(url, headers=headers, verify=False, timeout=CONFIG["REQUEST_TIMEOUT"])
        response.raise_for_status()
        
        data = response.json().get("data", {})
        os_info = data.get("affected_items", [])
        for item in os_info:
            item["agent_id"] = agent_id
        
        logger.info(f"📦 Fetched OS info for agent {agent_id}")
        return os_info
        
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Error fetching OS info for agent {agent_id}: {e}")
        return []

# --- OpenSearch Integration ---
def fetch_opensearch_alerts(session):
    try:
        auth = (CONFIG["OPENSEARCH_USER"], CONFIG["OPENSEARCH_PASS"])
        
        # Fetch all alerts except those from agent 000
        query = {
            "query": {
                "bool": {
                    "must_not": [{"term": {"agent.id": "000"}}]
                }
            },
            "sort": [
                {"@timestamp": {"order": "asc"}},
                {"_id": "asc"}  # Secondary sort for stability
            ],
            "size": 1000
        }
        
        all_alerts = []
        search_after = None
        page = 0
        
        while page < CONFIG["MAX_ALERT_PAGES"]:
            try:
                if search_after:
                    query["search_after"] = search_after
                
                response = session.get(
                    f"{CONFIG['OPENSEARCH_URL']}/{CONFIG['OPENSEARCH_INDEX']}/_search",
                    auth=auth,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps(query),
                    verify=False,
                    timeout=60
                )
                response.raise_for_status()
                
                data = response.json()
                hits = data["hits"]["hits"]
                total_alerts = data["hits"]["total"]["value"]
                
                if not hits:
                    break
                    
                for hit in hits:
                    alert = hit["_source"]
                    alert["_opensearch_id"] = hit["_id"]  # Store OpenSearch ID
                    all_alerts.append(alert)
                
                last_hit = hits[-1]
                if "sort" in last_hit and last_hit["sort"]:
                    search_after = last_hit["sort"]
                
                logger.info(f"📦 Fetched page {page+1}: {len(hits)} alerts (total: {len(all_alerts)}/{total_alerts})")
                
                if len(hits) < 1000:
                    break
                    
                page += 1
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"❌ Error fetching OpenSearch alerts page {page+1}: {e}")
                break
        
        # Ensure agent ID exists
        for alert in all_alerts:
            if "agent" not in alert:
                alert["agent"] = {}
            if "id" not in alert["agent"]:
                alert["agent"]["id"] = "unknown"
                alert["agent_id"] = "unknown"
            else:
                alert["agent_id"] = alert["agent"]["id"]
        
        logger.info(f"✅ Total fetched alerts: {len(all_alerts)}")
        return all_alerts
        
    except Exception as e:
        logger.error(f"❌ Error fetching OpenSearch alerts: {e}")
        return []

# --- Alert Processing ---
def process_alerts(alerts):
    """Enrich alerts with assessment metadata"""
    processed = []
    for alert in alerts:
        level = alert.get('rule', {}).get('level', 0)
        if level >= 12: 
            alert['_risk_score'] = "critical"
        elif level >= 8: 
            alert['_risk_score'] = "high"
        elif level >= 5: 
            alert['_risk_score'] = "medium"
        else:
            alert['_risk_score'] = "low"
        
        alert['_assessment_category'] = "configuration"
        processed.append(alert)
    return processed

# --- Categorization Logic ---
def categorize_log(log, log_type):
    if log_type == "manager_logs":
        msg = log.get("message", "").lower()
        if "authentication" in msg or "login" in msg:
            return "authentication_failures"
        elif "syscheck" in msg or "integrity" in msg:
            return "file_integrity_alerts"
        elif "usb" in msg or "udevd" in msg:
            return "usb_connections"
        elif "malware" in msg or "clamav" in msg:
            return "malware_alerts"
        elif "configuration" in msg:
            return "configuration_changes"
        elif "firewalld" in msg or "iptables" in msg:
            return "network_attacks"
        elif "sudo" in msg or "privilege" in msg:
            return "privilege_escalation"
        elif "unauthorized" in msg or "denied" in msg:
            return "unauthorized_access"
        return "others"
    
    # Map log types to categories
    category_map = {
        "syscheck": "event",
        "sca": "name",
        "software_inventory": "format",
        "manager_config": "core_configuration",
        "rules": "detection_rules",
        "os_info": "system_inventory",
        "alerts": lambda x: x.get('rule', {}).get('description', 'configuration_alert')[:50].replace(" ", "_")
    }
    
    if log_type in category_map:
        if callable(category_map[log_type]):
            return category_map[log_type](log)
        return log.get(category_map[log_type], "unknown")
    
    return "default"

# --- MongoDB Operations ---
def save_to_mongo(collection_name, logs, log_type):
    # Fix: Use explicit None check instead of boolean testing
    if not CONFIG["ENABLE_MONGODB_UPLOAD"] or db is None or not logs:
        logger.info(f"ℹ️ Skipping MongoDB upload for {log_type}")
        return

    try:
        collection = db[collection_name]
        inserted_count = 0

        # State-based collections (upsert)
        if log_type in ["software_inventory", "os_info", "manager_config"]:
            bulk_ops = []
            for log in logs:
                log["log_type"] = log_type
                log["_category"] = categorize_log(log, log_type)
                log["_fetched_at"] = datetime.now(timezone.utc)
                
                filter_criteria = {"agent_id": log.get("agent_id", "")}
                if log_type == "software_inventory":
                    filter_criteria.update({
                        "name": log.get("name", ""),
                        "version": log.get("version", "")
                    })
                elif log_type == "manager_config":
                    filter_criteria = {"type": "manager_config"}
                
                bulk_ops.append(pymongo.UpdateOne(
                    filter_criteria,
                    {"$set": log},
                    upsert=True
                ))
            
            if bulk_ops:
                result = collection.bulk_write(bulk_ops)
                inserted_count = result.upserted_count
                logger.info(f"✅ Upserted {len(bulk_ops)} {log_type} documents ({inserted_count} new)")
        
        # Alert collection (insert new only)
        elif log_type == "alerts":
            bulk_ops = []
            for alert in logs:
                alert["log_type"] = log_type
                alert["_category"] = categorize_log(alert, log_type)
                alert["_fetched_at"] = datetime.now(timezone.utc)
                
                # Use OpenSearch ID for deduplication
                alert_id = alert.get("_opensearch_id", "")
                if not alert_id:
                    continue
                
                bulk_ops.append(pymongo.UpdateOne(
                    {"_id": alert_id},
                    {"$setOnInsert": alert},
                    upsert=True
                ))
            
            if bulk_ops:
                result = collection.bulk_write(bulk_ops)
                inserted_count = result.upserted_count
                logger.info(f"✅ Inserted {inserted_count} new alerts")
        
        # Event-based collections (insert new only)
        else:
            bulk_ops = []
            for log in logs:
                log["log_type"] = log_type
                log["_category"] = categorize_log(log, log_type)
                log["_log_hash"] = hashlib.sha256(
                    json.dumps(log, sort_keys=True).encode()
                ).hexdigest()
                log["_fetched_at"] = datetime.now(timezone.utc)
                
                bulk_ops.append(pymongo.UpdateOne(
                    {"_log_hash": log["_log_hash"]},
                    {"$setOnInsert": log},
                    upsert=True
                ))
            
            if bulk_ops:
                result = collection.bulk_write(bulk_ops)
                inserted_count = result.upserted_count
                logger.info(f"✅ Inserted {inserted_count} new {log_type} logs")
            
    except Exception as e:
        logger.error(f"❌ Error saving to MongoDB: {e}")

# --- File Operations ---
def save_to_file(filename, data):
    if not CONFIG["SAVE_TO_FILE"] or not data:
        return
    
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"💾 Saved {len(data) if isinstance(data, list) else 1} items to {filename}")
    except Exception as e:
        logger.error(f"❌ Error saving to {filename}: {e}")

# --- Agent Data Processing ---
def process_agent_data(token, agent):
    session = create_session()  # Create a new session for each thread
    agent_id = agent["id"]
    logger.info(f"🔍 Processing agent {agent_id} ({agent['name']})")
    
    data = {
        "syscheck": fetch_syscheck(session, token, agent_id),
        "sca": fetch_sca(session, token, agent_id),
        "software_inventory": fetch_software_inventory(session, token, agent_id),
        "os_info": fetch_os_info(session, token, agent_id)
    }
    return agent_id, data

# --- Main Workflow ---
def run():
    start_time = datetime.now(timezone.utc)
    logger.info(f"🔄 Starting log fetch at {start_time}")
    
    session = create_session()
    token = get_token(session)
    if not token:
        logger.error("❌ Aborting due to authentication failure")
        return
    
    # Fetch agents and rules
    agents = fetch_agents(session, token)
    rules = fetch_rules(session, token)
    
    save_to_file("agents.json", agents)
    save_to_file("rules.json", rules)
    logger.info(f"👥 Agent count: {len(agents)}, Rules: {len(rules)}")
    
    # Process agents in parallel
    all_data = {
        "syscheck": [],
        "sca": [],
        "software_inventory": [],
        "os_info": []
    }
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["MAX_WORKERS"]) as executor:
        futures = [executor.submit(process_agent_data, token, agent) for agent in agents]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                agent_id, agent_data = future.result()
                for key in all_data:
                    all_data[key].extend(agent_data[key])
            except Exception as e:
                logger.error(f"❌ Error processing agent: {e}")
    
    # Save agent data
    for data_type, items in all_data.items():
        save_to_file(f"{data_type}.json", items)
        logger.info(f"💾 Saved {len(items)} {data_type.replace('_', ' ')}")
    
    # Process OpenSearch alerts
    raw_alerts = fetch_opensearch_alerts(session)
    processed_alerts = process_alerts(raw_alerts)
    save_to_file("alerts.json", processed_alerts)
    logger.info(f"🚨 Processed {len(processed_alerts)} alerts")
    
    # MongoDB saving
    if CONFIG["ENABLE_MONGODB_UPLOAD"]:
        save_to_mongo("agents", agents, "agents")
        save_to_mongo("rules", rules, "rules")
        for data_type, items in all_data.items():
            save_to_mongo(data_type, items, data_type)
        save_to_mongo("alerts", processed_alerts, "alerts")
    
    duration = datetime.now(timezone.utc) - start_time
    logger.info(f"✅ Log fetch completed in {duration.total_seconds():.2f} seconds")

# --- Main Execution ---
if __name__ == "__main__":
    # Initial run
    run()
    
    # Schedule periodic runs
    logger.info("🕒 Scheduler started. Fetching logs every 15 minutes...")
    schedule.every(15).minutes.do(run)
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    except KeyboardInterrupt:
        logger.info("🔚 Shutting down script")
        if client:
            client.close()
            logger.info("✅ MongoDB client connection closed")
        sys.exit(0)