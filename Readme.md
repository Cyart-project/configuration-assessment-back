# Wazuh to MongoDB Backend Integration Manual

## Overview

This service integrates Wazuh security monitoring with MongoDB, enabling real-time alert ingestion, periodic agent data collection, and API access for security data analysis. It provides centralized storage and management of Wazuh security data in MongoDB, supporting security configuration assessment and monitoring.

## Key Features

- **Webhook Receiver**: Processes Wazuh alerts in real-time.
- **Agent Data Collection**: Periodically collects syscheck, software inventory, and OS information.
- **Data Enrichment**: Adds risk scores and categorizations to alerts.
- **Efficient Storage**: Deduplicates and stores data in MongoDB.
- **REST API**: Provides endpoints for frontend integration.
- **Parallel Processing**: Optimizes data collection for large deployments.
- **Graceful Shutdown**: Ensures clean termination of processes.
- **Comprehensive Logging**: Facilitates monitoring and troubleshooting.

## Table of Contents

 1. [Prerequisites](#prerequisites)
 2. [Dependencies](#dependencies)
 3. [Setup and Installation](#setup-and-installation)
 4. [Configuration](#configuration)
 5. [Wazuh Integration Setup](#wazuh-integration-setup)
 6. [Execution](#execution)
 7. [API Endpoints](#api-endpoints)
 8. [Data Model](#data-model)
 9. [Operational Notes](#operational-notes)
10. [Troubleshooting](#troubleshooting)
11. [Security Considerations](#security-considerations)
12. [Scaling Recommendations](#scaling-recommendations)

---
<a name="prerequisites"></a>
## Prerequisites

Before setting up the integration, ensure the following requirements are met:

- **Python**: Version 3.9 or higher.
- **MongoDB**: MongoDB Atlas cluster or local instance (v5.0+).
- **Wazuh**: Wazuh Manager (v4.4+) with agents installed on monitored systems.
- **Network Access**:
  - Wazuh Manager to this service (port 5000).
  - This service to MongoDB (default port 27017).
  - This service to Wazuh API (default port 55000).

---
<a name="dependencies"></a>
## Dependencies

Install the required Python packages using the provided `requirements.txt`:

```bash
pip install -r requirements.txt
```
<a name="requirements"></a>
### requirements.txt

```text
Flask==3.1.1
flask-cors==6.0.1
pymongo==4.13.2
python-dotenv==1.1.1
requests==2.32.4
schedule==1.2.2
urllib3==2.5.0
```

---
<a name="setup-and-installation"></a>
## Setup and Installation

Follow these steps in order to set up the Wazuh-MongoDB integration service:

1. **Clone the Repository**

   ```bash
   git clone https://github.com/Cyart-project/configuration-assessment-back.git
   cd configuration-assessment-back
   ```

2. **Create a Virtual Environment**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**Create a `.env` file in the project root (see Configuration below).

5. **Set Up Wazuh Manager**Configure the Wazuh Manager and copy webhook scripts (see Wazuh Integration Setup below).

6. **Start the Service**Ensure the Wazuh Manager is running, then execute the service (see Execution below).

---
<a name="configuration"></a>
## Configuration

Configure the integration service and Wazuh Manager to work together.

### 1. Environment Variables

Create a `.env` file in the project root with the following content:

```ini
# MongoDB connection
MONGO_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/?retryWrites=true&w=majority

# Wazuh API credentials
# Common default credentials: user=admin, password=admin
WAZUH_API_URL=https://<wazuh_manager_ip>:55000
WAZUH_USER=api_user
WAZUH_PASS=api_password
```

Replace `<username>`, `<password>`, `<wazuh_manager_ip>`, `api_user`, and `api_password` with your actual MongoDB credentials, Wazuh Manager IP, and Wazuh API credentials.

### 2. Wazuh Manager Configuration

Edit the Wazuh configuration file to set up the webhook integration:

you can edit the wazuh configuration from wazuh dashboard directly 

OR

```bash
# Edit /var/ossec/etc/ossec.conf
sudo nano /var/ossec/etc/ossec.conf
```

Add the following integration block:

```xml
<ossec_config>
  <integration>
    <name>webhook</name>
    <hook_url>http://<this_server_ip>:5000/wazuh-alert</hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

Replace `<this_server_ip>` with the IP address of the server hosting this integration service.

Restart the Wazuh Manager to apply changes:

```bash
sudo systemctl restart wazuh-manager
```

---
<a name="wazuh-integration-setup"></a>
## Wazuh Integration Setup

To enable the webhook functionality, copy the provided scripts (`webhook.py` and `webhook.sh`) to the Wazuh Manager's integrations directory.

### Accessing the Wazuh Manager

- **If using a Wazuh VM**:
  - Login directly 
  OR
  - SSH into the Wazuh VM:

    ```bash
    ssh <wazuh_user>@<wazuh_vm_ip>
    ```

    Example default credentials: `wazuh_user=wazuh-user`, `password=wazuh` or `wazuh_user=admin`, `password=admin`.
  - Alternatively, log in directly if you have console access to the VM.
- **If Wazuh is installed locally**:
  - Access the system directly where Wazuh is installed (no SSH required).

### Copying Webhook Scripts

The integrations directory (`/var/ossec/integrations`) already exists in a standard Wazuh installation. Copy the scripts as follows:

```bash
# Copy webhook.py to Wazuh
sudo cp webhook.py /var/ossec/integrations/webhook.py
sudo chmod 750 /var/ossec/integrations/webhook.py
sudo chown root:wazuh /var/ossec/integrations/webhook.py

# Copy webhook.sh to Wazuh
sudo cp webhook.sh /var/ossec/integrations/webhook.sh
sudo chmod 750 /var/ossec/integrations/webhook.sh
sudo chown root:wazuh /var/ossec/integrations/webhook.sh
```

### Verify Script Permissions

Ensure the scripts have the correct permissions and ownership:

```bash
ls -l /var/ossec/integrations/
```

Expected output:

```
-rwxr-x--- 1 root wazuh ... webhook.py
-rwxr-x--- 1 root wazuh ... webhook.sh
```
<a name="execution"></a>
## Execution

Start the integration service after ensuring the Wazuh Manager is running.

1. **Activate Virtual Environment**

   ```bash
   source .venv/bin/activate 
   ```

2. **Run the Service**

   ```bash
   python3 wazuh_to_mongodb_integrated.py
   ```

3. **Verify Startup**Check the logs for successful startup:

   ```
   Successfully connected to MongoDB
   Starting webhook receiver on 0.0.0.0:5000
   Starting periodic data collection
   ```

---
<a name="api-endpoints"></a>
## API Endpoints

The service provides the following REST API endpoints:

| Endpoint | Method | Description | Parameters |
| --- | --- | --- | --- |
| `/wazuh-alert` | POST | Receives Wazuh alerts via webhook | None |
| `/api/agents` | GET | Lists all registered agents | None |
| `/api/agents/<agent_id>/alerts` | GET | Retrieves alerts for a specific agent | None |
| `/api/agents/<agent_id>/syscheck` | GET | Retrieves file integrity data for an agent | None |
| `/api/agents/<agent_id>/software` | GET | Retrieves software inventory for an agent | None |
| `/api/agents/<agent_id>/osinfo` | GET | Retrieves OS information for an agent | None |
| `/api/alerts` | GET | Retrieves all alerts | `risk_score`, `agent_id`, `limit` |

---
<a name="data-model"></a>
## Data Model

The service organizes data into MongoDB collections with the following structure:

### Collections

1. **alerts**: Stores Wazuh security alerts.
2. **agents**: Stores registered Wazuh agents.
3. **syscheck**: Stores file integrity monitoring data.
4. **software_inventory**: Stores installed software packages.
5. **os_info**: Stores operating system information.

### Alert Enrichment

- `_risk_score`: Critical, high, medium, or low.
- `_assessment_category`: Configuration.
- `_processed_at`: Timestamp of processing.
- `agent_id`: Normalized agent identifier.

### Syscheck Data

- `mtime`: Last modification time.
- `path`: File path.
- `size`: File size.
- `agent_id`: Source agent.
- `_category`: File category.
- `_fetched_at`: Collection timestamp.

---
<a name="operational-notes"></a>
## Operational Notes

- **Components**: The service runs a Flask-based webhook receiver (port 5000) and a scheduled data collector (every 15 minutes).
- **Initial Data Collection**: Performed on startup; may take time for large agent counts.
- **Shutdown**: Use `Ctrl+C` for graceful shutdown, which stops scheduled jobs, shuts down the web server, and closes MongoDB connections.
- **Logging**: Logs are output to stdout/stderr with timestamps for data collection progress.

### Startup Sequence

1. Connect to MongoDB.
2. Start webhook receiver in a background thread.
3. Perform initial data collection.
4. Schedule periodic data collection (every 15 minutes).
5. Monitor for shutdown signals.

### Graceful Shutdown

On SIGINT or SIGTERM:

1. Stop scheduled jobs.
2. Shut down the web server.
3. Close MongoDB connections.
4. Exit the process.

---
<a name="troubleshooting"></a>
## Troubleshooting

### Common Issues

| Symptom | Possible Cause | Solution |
| --- | --- | --- |
| MongoDB connection failed | Invalid MONGO_URI or network issue | Verify URI and test connectivity. |
| Wazuh API authentication failure | Invalid credentials | Check WAZUH_USER and WAZUH_PASS. |
| No alerts in database | Webhook misconfigured | Verify ossec.conf integration block. |
| Slow data collection | Large agent count | Increase MAX_WORKERS in script. |
| High CPU/memory usage | Large dataset | Add MongoDB indexes and scale resources. |

### Log Analysis

- **Successful Startup**:

  ```
  Successfully connected to MongoDB
  Starting webhook receiver on 0.0.0.0:5000
  Starting periodic data collection
  ```
- **Data Collection**:

  ```
  Fetching agents...
  Fetched 25 active agents
  Processing agent 001 (server01)
  ```
- **Shutdown**:

  ```
  Received signal 2, initiating graceful shutdown...
  Performing cleanup tasks...
  Web server stopped
  MongoDB connection closed
  ```

---

<a name="security-considerations"></a>
## Security Considerations

1. **Authentication**:
   - Implement API token authentication for endpoints.
   - Secure Wazuh API credentials in `.env`.
2. **Encryption**:
   - Use HTTPS for all communications.
   - Enable TLS for MongoDB connections.
3. **Network Security**:
   - Restrict MongoDB access to specific IPs.
   - Configure firewall rules for ports 5000 and 27017.
4. **Credentials Management**:
   - Use a secret management system (e.g., Vault, AWS Secrets Manager).
   - Rotate credentials regularly.
5. **Auditing**:
   - Monitor access logs for suspicious activity.
   - Implement rate limiting on API endpoints.

---

<a name="scaling-recommendations"></a>
## Scaling Recommendations

- **Horizontal Scaling**:
  - Use a load balancer for the webhook receiver.
  - Implement a message queue (e.g., RabbitMQ, Kafka) for alert ingestion.
- **Database**:
  - Add indexes on frequently queried fields.
  - Use sharding for large datasets.
  - Implement TTL indexes for automatic data expiration.
- **Performance**:
  - Increase MAX_WORKERS for large deployments.
  - Use caching (e.g., Redis) for frequent queries.
- **High Availability**:
  - Deploy multiple instances behind a load balancer.
  - Implement health checks and auto-recovery mechanisms.

  ---
