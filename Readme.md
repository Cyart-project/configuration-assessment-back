# Wazuh-MongoDB Integration Service

## Overview
This service integrates Wazuh security monitoring with MongoDB, providing:
- Real-time alert ingestion via webhook
- Periodic collection of agent data (syscheck, software inventory, OS info)
- Data enrichment and categorization
- API endpoints for frontend access to security data

The solution enables centralized storage and analysis of Wazuh security data in MongoDB, facilitating security configuration assessment and monitoring.

## Key Features
- Webhook receiver for Wazuh alerts
- Automated collection of agent security data
- Risk scoring and categorization of alerts
- Deduplication and efficient storage in MongoDB
- REST API for frontend integration
- Parallel processing for efficient data collection
- Graceful shutdown capabilities
- Comprehensive logging and error handling

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Dependencies](#dependencies)
3. [Configuration](#configuration)
4. [Installation & Execution](#installation--execution)
5. [API Endpoints](#api-endpoints)
6. [Data Model](#data-model)
7. [Operational Notes](#operational-notes)
8. [Known Limitations](#known-limitations)
9. [Troubleshooting](#troubleshooting)
10. [Security Considerations](#security-considerations)
11. [Scaling Recommendations](#scaling-recommendations)

<a name="prerequisites"></a>
## Prerequisites
- Python 3.9+
- MongoDB Atlas cluster or local MongoDB instance (v5.0+)
- Wazuh Manager (v4.4+)
- Wazuh agents installed on monitored systems
- Network access between:
  - Wazuh Manager → This service (port 5000)
  - This service → MongoDB (default port 27017)
  - This service → Wazuh API (port 55000)

<a name="dependencies"></a>
## Dependencies
Install required packages:

```bash
pip install -r requirements.txt 
```
OR 

```bash
pip install Flask flask-cors python-dotenv pymongo requests urllib3 schedule
```

### requirements.txt
```
Flask==3.1.1
flask-cors==6.0.1
pymongo==4.13.2
python-dotenv==1.1.1
requests==2.32.4
schedule==1.2.2
urllib3==2.5.0
```

<a name="configuration"></a>
## Configuration

### 1. Environment Variables
Create `.env` file in project root:
```ini
# MongoDB connection
MONGO_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/?retryWrites=true&w=majority

# Wazuh API credentials
WAZUH_API_URL=https://<wazuh_manager_ip>:55000
WAZUH_USER=api_user
WAZUH_PASS=api_password

```

### 2. Wazuh Manager Configuration
```bash
# Edit /var/ossec/etc/ossec.conf 
<ossec_config>
  <integration>
    <name>webhook</name>
    <hook_url>http://<this_server_ip>:5000/wazuh-alert</hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>

# Restart Wazuh manager
sudo systemctl restart wazuh-manager
```

<a name="installation--execution"></a>
## Installation & Execution

### Manual Execution

> **❗️ Pre-requisite:**  
> Make sure your Wazuh Manager service is up and running **before** you start this integration service.

```bash
# Clone repository
git clone https://github.com/Cyart-project/configuration-assessment-back.git
cd configuration-assessment-back

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies if not done already
pip install -r requirements.txt

# Run the service
python3 wazuh_to_mongodb_integrated.py
```

<a name="api-endpoints"></a>
## API Endpoints
| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/wazuh-alert` | POST | Webhook for Wazuh alerts | None |
| `/api/agents` | GET | Get all registered agents | None |
| `/api/agents/<agent_id>/alerts` | GET | Get alerts for specific agent | None |
| `/api/agents/<agent_id>/syscheck` | GET | Get file integrity data for agent | None |
| `/api/agents/<agent_id>/software` | GET | Get software inventory for agent | None |
| `/api/agents/<agent_id>/osinfo` | GET | Get OS information for agent | None |
| `/api/alerts` | GET | Get all alerts | `risk_score`, `agent_id`, `limit` |

<a name="data-model"></a>
## Data Model

### Collections
1. **alerts** - Wazuh security alerts
2. **agents** - Registered Wazuh agents
3. **syscheck** - File integrity monitoring data
4. **software_inventory** - Installed software packages
5. **os_info** - Operating system information

### Alert Enrichment
- `_risk_score`: critical, high, medium, low
- `_assessment_category`: configuration
- `_processed_at`: Timestamp of processing
- `agent_id`: Normalized agent identifier

### Syscheck Data
- `mtime`: Last modification time
- `path`: File path
- `size`: File size
- `agent_id`: Source agent
- `_category`: File category
- `_fetched_at`: Collection timestamp

<a name="operational-notes"></a>
## Operational Notes
- Service runs two main components:
  1. Webhook receiver (Flask app on port 5000)
  2. Scheduled data collector (runs every 15 minutes)
- First run will perform initial data collection (may take time depending on agent count)
- Use Ctrl+C for graceful shutdown
- Logs are output to stdout/stderr
- Data collection progress is logged with timestamps

### Startup Sequence
1. Initialize MongoDB connection
2. Start webhook receiver in background thread
3. Perform initial data collection
4. Schedule periodic collection every 15 minutes
5. Enter main loop checking for scheduled tasks and shutdown signals

### Graceful Shutdown
On receiving SIGINT or SIGTERM:
1. Stop all scheduled jobs
2. Shutdown web server
3. Close MongoDB connection
4. Exit process

<a name="known-limitations"></a>
## Known Limitations
- **Large deployments**: 
  - Syscheck collection for agents with many files may be slow
  - Consider increasing MAX_WORKERS for >100 agents
- **Security**: 
  - No authentication on API endpoints (add in production)
  - Self-signed certificates not verified
- **Data volume**:
  - No automatic data purging/archiving
  - MongoDB storage needs monitoring
- **Error handling**:
  - Some API errors may require manual intervention
  - Transient network errors are retried automatically

<a name="troubleshooting"></a>
## Troubleshooting

### Common Issues
| Symptom | Possible Cause | Solution |
|---------|----------------|----------|
| MongoDB connection failed | Invalid URI, network issue | Verify MONGO_URI, test connectivity |
| Wazuh API authentication failure | Invalid credentials | Verify Wazuh user/password |
| No alerts in database | Webhook not configured | Check Wazuh integration config |
| Slow data collection | Large agent count | Increase MAX_WORKERS |
| High CPU/Memory | Large dataset | Add MongoDB indexes, scale resources |

### Log Analysis
- **Successful startup**:
  ```
  Successfully connected to MongoDB
  Starting webhook receiver on 0.0.0.0:5000
  Starting periodic data collection
  ```

- **Data collection**:
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

<a name="security-considerations"></a>
## Security Considerations
1. **Authentication**:
   - Add API token authentication for endpoints
   - Secure Wazuh API credentials
2. **Encryption**:
   - Use HTTPS for all communications
   - Enable TLS for MongoDB connections
3. **Network Security**:
   - Restrict MongoDB network access
   - Firewall rules for service ports
4. **Credentials Management**:
   - Use secret management system (Vault, AWS Secrets Manager)
   - Regularly rotate credentials
5. **Auditing**:
   - Monitor access logs
   - Implement rate limiting

<a name="scaling-recommendations"></a>
## Scaling Recommendations
- **Horizontal Scaling**:
  - Add load balancing for webhook receiver
  - Implement message queue (RabbitMQ, Kafka) for alert ingestion
- **Database**:
  - Add MongoDB indexes on query fields
  - Implement sharding for large datasets
  - Use TTL indexes for automatic data expiration
- **Performance**:
  - Increase MAX_WORKERS for larger deployments
  - Implement caching for frequent queries (Redis)
- **High Availability**:
  - Deploy multiple instances behind load balancer
  - Implement health checks and auto-recovery

---
