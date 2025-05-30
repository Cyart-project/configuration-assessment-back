from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timezone
from bson import ObjectId
from urllib.parse import quote_plus
import logging
from contextlib import asynccontextmanager
import re
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB setup
username = quote_plus(os.getenv("MONGO_USERNAME"))
password = quote_plus(os.getenv("MONGO_PASSWORD"))
cluster = os.getenv("MONGO_CLUSTER")

MONGO_URI = f"mongodb+srv://{username}:{password}@{cluster}/?retryWrites=true&w=majority&appName=WazuhLogsDB"


mongo_client = AsyncIOMotorClient(MONGO_URI)
log_db = mongo_client["logdb"]
wazuh_db = mongo_client["wazuh_logs"]

# Collections
logs_collection = log_db["uploaded_logs"]
agent_events_collection = wazuh_db["agent_events"]

# Lifespan event handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Configuration Assessment API...")
    try:
        # Verify MongoDB connection
        await mongo_client.admin.command('ping')
        logger.info("Connected to MongoDB")
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        raise
    yield
    mongo_client.close()
    logger.info("MongoDB connection closed")

app = FastAPI(
    title="Configuration Assessment API",
    description="Extracts device configuration details from logs",
    version="1.0.0",
    lifespan=lifespan
)

# Pydantic models
class SoftwareItem(BaseModel):
    name: str
    version: str

class PeripheralDevice(BaseModel):
    type: str
    device_id: str
    timestamp: datetime

class AgentConfiguration(BaseModel):
    agent_id: str
    name: str
    ip: str
    os: Dict[str, str]
    last_seen: datetime
    status: str
    software: List[SoftwareItem] = []
    peripherals: List[PeripheralDevice] = []

class AgentSummary(BaseModel):
    agent_id: str
    name: str
    os: str
    status: str
    last_seen: datetime
    software_count: int

# Event patterns
EVENT_PATTERNS = {
    "software_installation": re.compile(
        r"(\d{4}-\d{2}-\d{2}) Installed (\w+) version (\S+)"
    ),
    "usb_connection": re.compile(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) USB device connected: (.+)"
    )
}

def extract_software_from_logs(logs: List[str]) -> List[SoftwareItem]:
    """Extract software installations from log entries"""
    software = []
    for log in logs:
        match = EVENT_PATTERNS["software_installation"].search(log)
        if match:
            date_str, name, version = match.groups()
            software.append(SoftwareItem(name=name, version=version))
    return software

def extract_peripherals_from_logs(logs: List[str]) -> List[PeripheralDevice]:
    """Extract peripheral connections from log entries"""
    peripherals = []
    for log in logs:
        match = EVENT_PATTERNS["usb_connection"].search(log)
        if match:
            timestamp_str, device_info = match.groups()
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            peripherals.append(PeripheralDevice(
                type="USB",
                device_id=device_info,
                timestamp=timestamp
            ))
    return peripherals

async def get_agent_events(agent_id: str) -> List[dict]:
    """Get all events for a specific agent"""
    events = []
    async for event in agent_events_collection.find({"id": agent_id}):
        events.append(event)
    return events

async def get_agent_logs(agent_id: str) -> List[str]:
    """Get all logs for a specific agent"""
    logs = []
    async for log in logs_collection.find({"agent_id": agent_id}):
        logs.append(log.get("log", ""))
    return logs

@app.get("/agent/{agent_id}/config", response_model=AgentConfiguration)
async def get_agent_config(agent_id: str):
    """Get complete configuration for an agent"""
    # Get agent details from events
    agent_events = await get_agent_events(agent_id)
    if not agent_events:
        raise HTTPException(404, "Agent not found")
    
    # Use the latest event for agent details
    latest_event = sorted(agent_events, key=lambda x: x.get("lastKeepAlive", ""), reverse=True)[0]
    
    # Get logs for software/peripherals
    logs = await get_agent_logs(agent_id)
    
    # Extract configuration details
    config = AgentConfiguration(
        agent_id=agent_id,
        name=latest_event.get("name", "Unknown"),
        ip=latest_event.get("ip", "0.0.0.0"),
        os=latest_event.get("os", {}),
        last_seen=datetime.fromisoformat(latest_event.get("lastKeepAlive", "1970-01-01T00:00:00")),
        status=latest_event.get("status", "unknown"),
        software=extract_software_from_logs(logs),
        peripherals=extract_peripherals_from_logs(logs)
    )
    return config

@app.get("/agents/summary", response_model=List[AgentSummary])
async def get_agents_summary():
    """Get summary of all agents with configuration highlights"""
    summary = []
    
    # Get all unique agent IDs from events
    agent_ids = set()
    async for event in agent_events_collection.find():
        agent_ids.add(event.get("id"))
    
    for agent_id in agent_ids:
        try:
            # Get basic agent info
            agent_events = await get_agent_events(agent_id)
            if not agent_events:
                continue
                
            latest_event = sorted(agent_events, key=lambda x: x.get("lastKeepAlive", ""), reverse=True)[0]
            
            # Get logs to count software
            logs = await get_agent_logs(agent_id)
            software_count = len(extract_software_from_logs(logs))
            
            summary.append(AgentSummary(
                agent_id=agent_id,
                name=latest_event.get("name", "Unknown"),
                os=latest_event.get("os", {}).get("name", "Unknown OS"),
                status=latest_event.get("status", "unknown"),
                last_seen=datetime.fromisoformat(latest_event.get("lastKeepAlive", "1970-01-01T00:00:00")),
                software_count=software_count
            ))
        except Exception as e:
            logger.error(f"Error processing agent {agent_id}: {str(e)}")
    
    return summary

@app.get("/health")
async def health_check():
    """Check API health"""
    try:
        await mongo_client.admin.command('ping')
        return {"status": "healthy", "timestamp": datetime.now(timezone.utc)}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

@app.get("/")
async def root():
    return {
        "message": "Configuration Assessment API",
        "endpoints": {
            "GET /agent/{agent_id}/config": "Get full agent configuration",
            "GET /agents/summary": "Get summary of all agents",
            "GET /health": "Health check"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")