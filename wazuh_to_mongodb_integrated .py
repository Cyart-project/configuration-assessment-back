import os
import json
import time
import logging
import sys
import hashlib
import threading
import concurrent.futures
import signal
from datetime import datetime, timezone
from urllib.parse import urlparse
from base64 import b64encode
from dotenv import load_dotenv
from flask import Flask, request, jsonify
import requests
import urllib3
import pymongo
import schedule
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask_cors import CORS
import atexit
from werkzeug.serving import make_server

# Load environment variables
load_dotenv("./.env")

# --- Configuration ---
CONFIG = {
    "MONGO_URI": os.getenv("MONGO_URI"),
    "WAZUH_API_URL": os.getenv("WAZUH_API_URL"),
    "WAZUH_USER": os.getenv("WAZUH_USER"),
    "WAZUH_PASS": os.getenv("WAZUH_PASS"),
    "ENABLE_MONGODB_UPLOAD": True,
    "MAX_SYSCHECK_PAGES": 100,
    "MAX_WORKERS": 5,
    "REQUEST_TIMEOUT": 30,
    "WEBHOOK_HOST": "0.0.0.0",
    "WEBHOOK_PORT": 5000,
    "RETRY_STRATEGY": {
        "total": 3,
        "backoff_factor": 1,
        "status_forcelist": [429, 500, 502, 503, 504]
    },
    "SHUTDOWN_TIMEOUT": 10  # Seconds to wait for graceful shutdown
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

#Global flag to signal shutdown
shutdown_event = threading.Event()
shutting_down = False
data_collection_lock = threading.Lock()

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global shutting_down
    if shutting_down:
        logger.info(" Forcing immediate shutdown")
        os._exit(1)  # Force immediate exit
    
    logger.info(f" Received signal {signum}, initiating graceful shutdown...")
    shutdown_event.set()
    shutting_down = True

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class StoppableServer(threading.Thread):
    """Custom thread class for Flask server with shutdown capability"""
    def __init__(self, app, host, port):
        super().__init__(daemon=True)
        self.app = app
        self.host = host
        self.port = port
        self.server = None
    
    def run(self):
        """Run the Flask server using Werkzeug's production server"""
        try:
            logger.info(f" Starting web server on {self.host}:{self.port}")
            self.server = make_server(self.host, self.port, self.app)
            self.server.serve_forever()
        except Exception as e:
            if not shutting_down:
                logger.error(f" Web server error: {e}")
    
    def shutdown(self):
        """Shutdown the Werkzeug server"""
        if self.server:
            logger.info(" Shutting down web server...")
            self.server.shutdown()
            self.join(timeout=CONFIG["SHUTDOWN_TIMEOUT"])
            if self.is_alive():
                logger.warning(" Web server thread did not terminate gracefully")
            else:
                logger.info(" Web server stopped")

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
        logger.info(" MongoDB upload is disabled via configuration")
        return None, None
    
    uri = CONFIG["MONGO_URI"]
    if not uri:
        logger.error(" MONGO_URI environment variable is not set")
        return None, None
    
    try:
        parsed = urlparse(uri)
        if not parsed.scheme.startswith("mongodb"):
            logger.error(" MONGO_URI must start with 'mongodb://' or 'mongodb+srv://'")
            return None, None
        
        # Mask credentials for logging
        masked_uri = uri
        if "@" in uri:
            user_part = uri.split("@")[0]
            masked_uri = uri.replace(user_part, "mongodb://****:****")
        logger.info(f" Using MONGO_URI: {masked_uri}")
        
        client = pymongo.MongoClient(uri)
        db = client["wazuh_config_assessment"]
        client.server_info()  # Test connection
        logger.info(" Successfully connected to MongoDB")
        return db, client
        
    except (ValueError, pymongo.errors.ConnectionFailure) as e:
        logger.error(f" MongoDB connection failed: {e}")
        return None, None

# Initialize MongoDB
db, mongo_client = init_mongodb()

# --- Webhook Receiver ---
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes


@app.before_request
def check_shutdown():
    """Block new requests during shutdown process"""
    if shutting_down:
        return jsonify({
            "status": "error",
            "message": "Server is shutting down, request rejected"
        }), 503

@app.route('/api/agents', methods=['GET'])
def get_agents():
    """Get all agents from MongoDB"""
    if db is None:
        return jsonify({"status": "error", "message": "MongoDB not connected"}), 500
    
    try:
        collection = db["agents"]
        agents = list(collection.find({}, {'_id': 0}))
        return jsonify({"status": "success", "data": agents}), 200
    except Exception as e:
        logger.error(f" Error fetching agents: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/agents/<agent_id>/alerts', methods=['GET'])
def get_agent_alerts(agent_id):
    """Get alerts for a specific agent"""
    if db is None:
        return jsonify({"status": "error", "message": "MongoDB not connected"}), 500
    
    try:
        collection = db["alerts"]
        alerts = list(collection.find(
            {"agent_id": agent_id},
            {'_id': 0},
            sort=[("timestamp", pymongo.DESCENDING)]
        ))
        return jsonify({"status": "success", "data": alerts}), 200
    except Exception as e:
        logger.error(f" Error fetching alerts for agent {agent_id}: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/agents/<agent_id>/syscheck', methods=['GET'])
def get_agent_syscheck(agent_id):
    """Get syscheck data for a specific agent"""
    if db is None:
        return jsonify({"status": "error", "message": "MongoDB not connected"}), 500
    
    try:
        collection = db["syscheck"]
        syscheck_data = list(collection.find(
            {"agent_id": agent_id},
            {'_id': 0},
            sort=[("mtime", pymongo.DESCENDING)]
        ))
        return jsonify({"status": "success", "data": syscheck_data}), 200
    except Exception as e:
        logger.error(f" Error fetching syscheck for agent {agent_id}: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/agents/<agent_id>/software', methods=['GET'])
def get_agent_software(agent_id):
    """Get software inventory for a specific agent"""
    if db is None:
        return jsonify({"status": "error", "message": "MongoDB not connected"}), 500
    
    try:
        collection = db["software_inventory"]
        software_data = list(collection.find(
            {"agent_id": agent_id},
            {'_id': 0},
            sort=[("name", pymongo.ASCENDING)]
        ))
        return jsonify({"status": "success", "data": software_data}), 200
    except Exception as e:
        logger.error(f" Error fetching software for agent {agent_id}: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/agents/<agent_id>/osinfo', methods=['GET'])
def get_agent_osinfo(agent_id):
    """Get OS info for a specific agent"""
    if db is None:
        return jsonify({"status": "error", "message": "MongoDB not connected"}), 500
    
    try:
        collection = db["os_info"]
        os_info = list(collection.find(
            {"agent_id": agent_id},
            {'_id': 0}
        ))
        return jsonify({"status": "success", "data": os_info}), 200
    except Exception as e:
        logger.error(f" Error fetching OS info for agent {agent_id}: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_all_alerts():
    """Get all alerts with optional filters"""
    if db is None:
        return jsonify({"status": "error", "message": "MongoDB not connected"}), 500
    
    try:
        # Get query parameters
        risk_score = request.args.get('risk_score')
        agent_id = request.args.get('agent_id')
        limit = int(request.args.get('limit', 100))
        
        query = {}
        if risk_score:
            query["_risk_score"] = risk_score
        if agent_id:
            query["agent_id"] = agent_id
        
        collection = db["alerts"]
        alerts = list(collection.find(
            query,
            {'_id': 0},
            sort=[("timestamp", pymongo.DESCENDING)],
            limit=limit
        ))
        return jsonify({"status": "success", "data": alerts}), 200
    except Exception as e:
        logger.error(f" Error fetching alerts: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/wazuh-alert', methods=['POST'])
def handle_alert():
    if db is None:  # FIXED: Use explicit None check
        return jsonify({"status": "error", "message": "MongoDB not connected"}), 500
    
    try:
        alert = request.get_json()
        if not alert:
            return jsonify({"status": "error", "message": "Empty payload"}), 400
        
        # Process and enrich alert
        processed_alert = process_alert(alert)
        
        # Use Wazuh alert ID for deduplication
        alert_id = processed_alert.get('id')
        if not alert_id:
            return jsonify({"status": "error", "message": "Missing alert ID"}), 400
        
        # Get collection
        collection = db["alerts"]
        
        # Insert or update alert
        result = collection.update_one(
            {"_id": alert_id},
            {"$set": processed_alert},
            upsert=True
        )
        
        if result.upserted_id:
            logger.info(f" Inserted new alert: {alert_id}")
        else:
            logger.info(f" Updated existing alert: {alert_id}")
        
        return jsonify({"status": "success"}), 200
    
    except Exception as e:
        logger.error(f" Error processing alert: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

def process_alert(alert):
    """Enrich alerts with assessment metadata"""
    # Add risk scoring
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
    
    # Ensure agent_id exists
    if 'agent' in alert and 'id' in alert['agent']:
        alert['agent_id'] = alert['agent']['id']
    else:
        alert['agent'] = alert.get('agent', {})
        alert['agent']['id'] = "unknown"
        alert['agent_id'] = "unknown"
    
    # Add processing timestamp
    alert['_processed_at'] = datetime.now(timezone.utc)
    
    return alert

def run_webhook():
    """Run the Flask webhook receiver with graceful shutdown capability"""
    server = StoppableServer(app, CONFIG["WEBHOOK_HOST"], CONFIG["WEBHOOK_PORT"])
    server.start()
    return server

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
        logger.info(" Authenticated with Wazuh API")
        return token
        
    except requests.exceptions.RequestException as e:
        logger.error(f" Error getting authentication token: {e}")
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
            logger.error(f" Error fetching data from {url}: {e}")
            break
            
    return items

def fetch_agents(session, token):
    logger.info(" Fetching agents...")
    agents = fetch_paginated_data(session, f"{CONFIG['WAZUH_API_URL']}/agents", token)
    filtered_agents = [agent for agent in agents if agent["id"] != "000"]
    logger.info(f" Fetched {len(filtered_agents)} active agents")
    return filtered_agents

def fetch_syscheck(session, token, agent_id):
    logger.info(f" Fetching syscheck for agent {agent_id}...")
    syscheck_logs = fetch_paginated_data(
        session, 
        f"{CONFIG['WAZUH_API_URL']}/syscheck/{agent_id}", 
        token
    )
    for log in syscheck_logs:
        log["agent_id"] = agent_id
    logger.info(f" Fetched {len(syscheck_logs)} syscheck logs for agent {agent_id}")
    return syscheck_logs

def fetch_software_inventory(session, token, agent_id):
    logger.info(f" Fetching software inventory for agent {agent_id}...")
    inventory = fetch_paginated_data(
        session,
        f"{CONFIG['WAZUH_API_URL']}/syscollector/{agent_id}/packages",
        token
    )
    for item in inventory:
        item["agent_id"] = agent_id
    logger.info(f" Fetched {len(inventory)} software items for agent {agent_id}")
    return inventory

def fetch_os_info(session, token, agent_id):
    logger.info(f" Fetching OS info for agent {agent_id}...")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{CONFIG['WAZUH_API_URL']}/syscollector/{agent_id}/os"
        response = session.get(url, headers=headers, verify=False, timeout=CONFIG["REQUEST_TIMEOUT"])
        response.raise_for_status()
        
        data = response.json().get("data", {})
        os_info = data.get("affected_items", [])
        for item in os_info:
            item["agent_id"] = agent_id
        
        logger.info(f" Fetched OS info for agent {agent_id}")
        return os_info
        
    except requests.exceptions.RequestException as e:
        logger.error(f" Error fetching OS info for agent {agent_id}: {e}")
        return []

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
        "software_inventory": "format",
        "os_info": "system_inventory"
    }
    
    if log_type in category_map:
        return log.get(category_map[log_type], "unknown")
    
    return "default"

# --- MongoDB Operations ---
def save_to_mongo(collection_name, logs, log_type):
    if not CONFIG["ENABLE_MONGODB_UPLOAD"] or db is None or not logs:
        logger.info(f" Skipping MongoDB upload for {log_type}")
        return

    try:
        collection = db[collection_name]
        inserted_count = 0

        # State-based collections (upsert)
        if log_type in ["software_inventory", "os_info"]:
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
                
                bulk_ops.append(pymongo.UpdateOne(
                    filter_criteria,
                    {"$set": log},
                    upsert=True
                ))
            
            if bulk_ops:
                result = collection.bulk_write(bulk_ops)
                inserted_count = result.upserted_count
                logger.info(f" Upserted {len(bulk_ops)} {log_type} documents ({inserted_count} new)")
        
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
                logger.info(f" Inserted {inserted_count} new {log_type} logs")
            
    except Exception as e:
        logger.error(f" Error saving to MongoDB: {e}")

# --- Agent Data Processing ---
def process_agent_data(token, agent):
    session = create_session()
    agent_id = agent["id"]
    logger.info(f" Processing agent {agent_id} ({agent['name']})")
    
    data = {
        "syscheck": fetch_syscheck(session, token, agent_id),
        "software_inventory": fetch_software_inventory(session, token, agent_id),
        "os_info": fetch_os_info(session, token, agent_id)
    }
    return agent_id, data

# --- Periodic Data Collection ---
def run_data_collection():
    """Run the data collection process with shutdown checks"""
    # Skip if already running or during shutdown
    if not data_collection_lock.acquire(blocking=False):
        logger.info(" Data collection already in progress, skipping")
        return
    
    try:
        if shutdown_event.is_set():
            logger.info(" Skipping data collection during shutdown")
            return
        
        start_time = datetime.now(timezone.utc)
        logger.info(f" Starting periodic data collection at {start_time}")
        
        session = create_session()
        token = get_token(session)
        if not token:
            logger.error(" Aborting due to authentication failure")
            return
        
        # Fetch agents
        agents = fetch_agents(session, token)
        if shutdown_event.is_set() or not agents:
            logger.info(" Aborting data collection during shutdown")
            return
        
        logger.info(f" Fetched {len(agents)} active agents")
        
        # Process agents in parallel
        all_data = {
            "syscheck": [],
            "software_inventory": [],
            "os_info": []
        }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["MAX_WORKERS"]) as executor:
            futures = []
            for agent in agents:
                if shutdown_event.is_set():
                    logger.info(" Cancelling agent processing during shutdown")
                    break
                futures.append(executor.submit(process_agent_data, token, agent))
            
            for future in concurrent.futures.as_completed(futures):
                if shutdown_event.is_set():
                    logger.info(" Cancelling remaining agent processing")
                    # Cancel unfinished futures
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    break
                try:
                    agent_id, agent_data = future.result()
                    for key in all_data:
                        all_data[key].extend(agent_data[key])
                except Exception as e:
                    logger.error(f" Error processing agent: {e}")
        
        # Skip MongoDB saving during shutdown
        if shutdown_event.is_set():
            logger.info(" Skipping MongoDB upload during shutdown")
            return
        
        # MongoDB saving
        if CONFIG["ENABLE_MONGODB_UPLOAD"] and db is not None:
            save_to_mongo("agents", agents, "agents")
            for data_type, items in all_data.items():
                save_to_mongo(data_type, items, data_type)
        
        duration = datetime.now(timezone.utc) - start_time
        logger.info(f" Periodic data collection completed in {duration.total_seconds():.2f} seconds")
    
    finally:
        data_collection_lock.release()

# --- Main Execution ---
def main():
    global shutting_down
    
    # Start webhook receiver in a separate thread
    webhook_thread = run_webhook()
    logger.info(" Webhook receiver started in background thread")
    
    # Register cleanup function
    atexit.register(cleanup_resources, webhook_thread)
    
    # Initial data collection
    run_data_collection()
    
    # Schedule periodic data collection
    logger.info(" Scheduler started. Collecting data every 15 minutes...")
    schedule.every(15).minutes.do(run_data_collection)
    
    # Keep main thread alive
    try:
        while not shutdown_event.is_set():
            schedule.run_pending()
            time.sleep(1)  # Check every second
    except Exception as e:
        logger.error(f" Unexpected error: {e}")
        shutdown_event.set()
    finally:
        logger.info(" Shutdown initiated, waiting for cleanup...")
        # Give some time for cleanup, but force exit if needed
        time.sleep(2)

def run_webhook():
    """Run the Flask webhook receiver with graceful shutdown capability"""
    server = StoppableServer(app, CONFIG["WEBHOOK_HOST"], CONFIG["WEBHOOK_PORT"])
    server.start()
    
    # Wait briefly to ensure server starts
    time.sleep(0.5)
    return server

def cleanup_resources(webhook_thread):
    """Clean up resources during shutdown"""
    global shutting_down
    shutting_down = True
    
    logger.info(" Performing cleanup tasks...")
    
    # Stop scheduled jobs
    schedule.clear()
    logger.info(" Stopped all scheduled jobs")
    
    # Shutdown web server
    if webhook_thread and webhook_thread.is_alive():
        webhook_thread.shutdown()
    
    # Close MongoDB connection
    if mongo_client:
        try:
            mongo_client.close()
            logger.info(" MongoDB connection closed")
        except Exception as e:
            logger.error(f" Error closing MongoDB connection: {e}")
    
    logger.info(" Shutdown complete")

if __name__ == "__main__":
    main()