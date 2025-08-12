import os
import json
import re
import requests
import pymongo
from collections import defaultdict
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Load environment variables ---
load_dotenv()

# --- Flask App Setup ---
app = Flask(__name__)
CORS(app)

# --- MongoDB & NVD Configuration ---
MONGO_URI = os.getenv("MONGO_URI")
NVD_API_KEY = os.getenv("NVD_API_KEY")

client = pymongo.MongoClient(MONGO_URI)
db = client["wazuh_config_assessment"]
agents_col = db["agents"]
software_col = db["software_inventory"]
osinfo_col = db["os_info"]
alerts_col = db["alerts"]
syscheck_col = db["syscheck"]

# --- Stop words for keyword filtering ---
STOP_WORDS = {
    "the", "and", "for", "with", "from", "software", "update", "security",
    "tool", "system", "user", "version", "client", "server", "application",
    "device", "service", "network", "management", "information"
}


# --- Helper Functions ---
def extract_keywords(text):
    words = re.findall(r"[a-zA-Z]+", text.lower())
    # Filter out stop words
    return [w for w in words if w not in STOP_WORDS]


def classify_risk(score):
    score = float(score)
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    return "Low"


def extract_remediation(vuln):
    refs = vuln.get("cve", {}).get("references", [])
    remediations = []
    for ref in refs:
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        if any(tag in tags for tag in ["Patch", "Vendor Advisory", "Third Party Advisory"]):
            remediations.append(url)
    if remediations:
        return {
            "summary": "Refer to vendor advisory or patch links provided.",
            "references": remediations
        }
    return {
        "summary": "No explicit remediation found. Check CVE description and vendor documentation.",
        "references": []
    }


def query_nvd(keyword):
    try:
        print(f"🔍 Searching CVEs for: {keyword}")
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 3},
            headers={"apiKey": NVD_API_KEY} if NVD_API_KEY else {},
            timeout=10
        )
        if not response.ok:
            print(f"❌ NVD query failed: {response.status_code} - {response.text[:100]}")
            return []
        data = response.json()
        vulns = data.get("vulnerabilities", [])
        return [{
            "cve_id": v["cve"]["id"],
            "cvss_score": v["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"],
            "description": v["cve"]["descriptions"][0]["value"],
            "risk_level": classify_risk(v["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]),
            "url": f"https://nvd.nist.gov/vuln/detail/{v['cve']['id']}",
            "remediation": extract_remediation(v)
        } for v in vulns if "cvssMetricV31" in v["cve"]["metrics"]]
    except Exception as e:
        print(f"❌ Error querying NVD: {e}")
        return []


def query_keyword(kw):
    return (kw, query_nvd(kw))


def generate_report(agent_id):
    print(f"\n📦 Generating CVE report for Agent ID: {agent_id}")
    agent = agents_col.find_one({"id": agent_id})
    if not agent:
        return {"error": "Agent not found."}, 404

    device = {
        "agent_id": agent_id,
        "device_name": agent.get("name", "Unknown"),
        "ip": agent.get("ip", "Unknown"),
        "os": agent.get("os", {}).get("name", "Unknown"),
        "last_seen": agent.get("lastKeepAlive", "Unknown")
    }

    # Prepare reverse map keyword -> software entries
    software_logs = list(software_col.find({"agent_id": agent_id}))
    keyword_to_software = defaultdict(list)

    for sw in software_logs:
        sw_name = sw.get("name", "")
        sw_scan_time = sw.get("scan", {}).get("time", "Unknown")
        keywords = extract_keywords(sw_name)
        for kw in keywords:
            keyword_to_software[kw].append({"name": sw_name, "timestamp": sw_scan_time})

    keywords = list(keyword_to_software.keys())

    matched_cves = []
    seen_cves = set()
    severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(query_keyword, kw) for kw in keywords]

        for future in as_completed(futures):
            kw, cves = future.result()
            for cve in cves:
                if cve["cve_id"] in seen_cves:
                    continue
                seen_cves.add(cve["cve_id"])
                for ref in keyword_to_software[kw]:
                    matched_cves.append({
                        "timestamp": ref["timestamp"],
                        "software": ref["name"],
                        **cve
                    })
                    severity_count[cve["risk_level"]] += 1

    alerts = list(alerts_col.find({"agent_id": agent_id}))
    sys_logs = list(syscheck_col.find({"agent_id": agent_id}))
    os_data = osinfo_col.find_one({"agent_id": agent_id}) or {}

    report = {
        "device_info": device,
        "os_details": os_data.get("os", {}),
        "summary": {
            "software_analyzed": len(software_logs),
            "alerts_found": len(alerts),
            "syscheck_entries": len(sys_logs),
            "total_cves": len(matched_cves),
            "severity_breakdown": severity_count
        },
        "findings": matched_cves
    }

    # Save JSON file
    filename = f"cve_report_{agent_id}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"✅ Report saved: {filename}")
    return report, 200


# --- Flask API Route ---
@app.route('/generate-report', methods=['POST'])
def handle_report():
    data = request.get_json(silent=True)
    print("📩 Received request body:", data)

    if not data or "agent_id" not in data:
        return jsonify({"error": "Missing 'agent_id' in request body"}), 400

    agent_id = data["agent_id"]
    report, status = generate_report(agent_id)
    return jsonify(report), status


# --- Run Flask App ---
if __name__ == "__main__":
    app.run(port=5001, debug=True)