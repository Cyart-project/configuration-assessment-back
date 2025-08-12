# CVE Report Generator

A Python-based Flask API that analyzes device-specific logs stored in MongoDB, queries vulnerabilities from the National Vulnerability Database (NVD), and generates a structured CVE report with severity, descriptions, and remediation steps.

---

## Overview

This tool is designed for cybersecurity use cases where agents (devices/endpoints) send system and software logs to a MongoDB database. When provided an `agent_id`, the tool:

- Extracts logs from MongoDB
- Parses keywords from software names
- Queries CVEs via the NVD API
- Matches and classifies vulnerabilities
- Generates a detailed JSON report

---

## Features

- Extracts relevant software data using keyword matching
- Integrates with the NVD CVE API (v2.0)
- Automatically classifies CVEs by CVSS score
- Outputs detailed JSON reports including:
  - CVE ID, description, CVSS score, severity level
  - Remediation suggestions and external references
- Modular and easy to extend

---

## Tech Stack

- **Backend:** Python, Flask
- **Database:** MongoDB
- **APIs:** NVD (National Vulnerability Database)
- **Environment Mgmt:** `python-dotenv`

---

## Project Structure

- Test.py # Main Flask app with logic
- .env # Your local config with secrets - not shared
- requirements.txt # Python dependencies
- README.md # This documentation
- Reports # Generated JSON report 


---

## Setup Instructions

1. **Clone the Repository**

- git clone https://github.com/Cyart-project/configuration-assessment-back.git
- cd your-project-directory

2. **Create and Configure .env File**

`# .env`<br>
`MONGO_URI=mongodb://localhost:27017`
`NVD_API_KEY=your_nvd_api_key_here`

3. **Install Python Dependencies**

`pip install -r requirements.txt`

4. **Run the Flask Server**

`Python Report_API.py`<br>

By default, the server runs at:<br>
`http://127.0.0.1:5001`

---

## How to Use the API

1. Endpoint: POST /generate-report

2. Request Body (JSON)
{
  "agent_id": 1
}

3. Response (Example)

{
  "device_info": {
    "agent_id": 1,
    "device_name": "ubuntu-vm",
    "ip": "192.168.0.101",
    "os": "Ubuntu 20.04",
    "last_seen": "2024-07-01T10:00:00"
  },
  "os_details": {...},
  "summary": 
    "software_analyzed": 7,
    "alerts_found": 5,
    "syscheck_entries": 12,
    "total_cves": 14,
    "severity_breakdown": {
      "Critical": 2,
      "High": 6, 
      "Medium": 4, 
      "Low": 2 
    } 
  }, 
  "findings": [
    {
      "timestamp": "2024-07-01T12:00:00",
      "software": "OpenSSL",
      "cve_id": "CVE-2023-37920",
      "cvss_score": 9.8,
      "risk_level": "Critical",<
      "description": "Buffer overflow in OpenSSL...",<
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-37920",
      "remediation": {
        "summary": "Refer to vendor advisory or patch links provided.",
        "references": ["https://openssl.org/security"]
      }
    }
  ]
}

---

## MongoDB Collections
Your database should include the following collections:

* Collection: Description
* agents: Device info: ID, name, IP, OS
* software_inventory: Installed software logs
* alerts: Alert logs from the agent
* syscheck: File integrity logs (changes)
* os_info: OS metadata and kernel version

---

## Dependencies
Install using 
pip install -r requirements.txt

**requirements.txt**
- Flask
- pymongo
- python-dotenv
- requests

---

## Known Limitations

- Rate Limiting: NVD API may limit your requests without an API key.

- Keyword Matching: CVE keyword search may result in false positives.

- CVSS Versions: Only CVSS v3.1 scores are considered.

- Duplicate Filtering: Same CVE across multiple software entries is deduplicated.

---

##  Output File

On success, the CVE report is saved locally as:
- cve_report_<agent_id>.json
