"""
Wazuh Report API
================

A production‑ready FastAPI micro‑service that aggregates security and vulnerability
information from Wazuh and returns it in a single JSON payload for the frontend
report page.

───────────────────────────────────────────────────────────────────────────────
⚙️ Environment variables (create a .env file or export in the shell)
───────────────────────────────────────────────────────────────────────────────
WAZUH_API_URL    # e.g. "https://wazuh-manager.local:55000"
WAZUH_USERNAME   # the Wazuh API user (default: "wazuh-wui")
WAZUH_PASSWORD   # the user’s password (⚠️ required)
VERIFY_SSL       # "true" to verify the manager's TLS certificate (default: false)
TOKEN_REFRESH_MARGIN # seconds before expiry to refresh the JWT (default: 60)

───────────────────────────────────────────────────────────────────────────────
📦 Dependencies
───────────────────────────────────────────────────────────────────────────────
python -m pip install fastapi uvicorn[standard] httpx[http2] python-dotenv pydantic

───────────────────────────────────────────────────────────────────────────────
▶️ Run locally
───────────────────────────────────────────────────────────────────────────────
uvicorn wazuh_report_api:app --reload --port 8000

Point the frontend to GET /report

───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from functools import lru_cache
from typing import List, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, BaseSettings, Field

###############################################################################
# Settings & configuration
###############################################################################

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    WAZUH_API_URL: str = Field("https://localhost:55000", env="WAZUH_API_URL")
    WAZUH_USERNAME: str = Field("wazuh-wui", env="WAZUH_USERNAME")
    WAZUH_PASSWORD: str = Field(..., env="WAZUH_PASSWORD")  # noqa: E501

    # SSL verification is strongly recommended in production.
    VERIFY_SSL: bool = Field(False, env="VERIFY_SSL")

    # Token refresh margin (seconds before expiry)
    TOKEN_REFRESH_MARGIN: int = Field(60, env="TOKEN_REFRESH_MARGIN")

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:  # pragma: no cover
    return Settings()  # type: ignore[arg-type]


###############################################################################
# Wazuh client (handles auth + requests)
###############################################################################

class WazuhClient:
    """Simple async wrapper around the Wazuh REST API with JWT caching."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._token: Optional[str] = None
        self._token_expiry: Optional[_dt.datetime] = None
        self._http = httpx.AsyncClient(
            base_url=settings.WAZUH_API_URL.rstrip("/"),
            verify=settings.VERIFY_SSL,
            timeout=30,
            headers={"Content-Type": "application/json"},
            http2=True,
        )

    # ────────────────────────────────────────────────────────────────── token ──
    async def _authenticate(self) -> None:
        resp = await self._http.post(
            "/security/user/authenticate",
            json={"username": self._settings.WAZUH_USERNAME, "password": self._settings.WAZUH_PASSWORD},
        )
        if resp.status_code != 200:
            logging.error("Wazuh auth failed %s %s", resp.status_code, resp.text)
            raise HTTPException(500, "Unable to authenticate with Wazuh manager")
        body = resp.json()["data"]
        self._token = body["token"]
        # Wazuh tokens are valid for 3600 s.
        self._token_expiry = _dt.datetime.utcnow() + _dt.timedelta(seconds=3600)
        logging.info("Authenticated with Wazuh – JWT cached until %s", self._token_expiry)

    async def _ensure_token(self) -> None:
        margin = _dt.timedelta(seconds=self._settings.TOKEN_REFRESH_MARGIN)
        if not self._token or not self._token_expiry or (_dt.datetime.utcnow() + margin) >= self._token_expiry:
            await self._authenticate()

    # ──────────────────────────────────────────────────────────── HTTP helpers ──
    async def get(self, path: str, **kwargs):
        await self._ensure_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        resp = await self._http.get(path, headers=headers, **kwargs)
        if resp.status_code == 401:  # token expired early
            await self._authenticate()
            headers["Authorization"] = f"Bearer {self._token}"
            resp = await self._http.get(path, headers=headers, **kwargs)
        if resp.status_code >= 400:
            logging.error("Wazuh GET %s failed %s", path, resp.text)
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()

    async def close(self):  # pragma: no cover
        await self._http.aclose()


###############################################################################
# Pydantic models for the API response
###############################################################################

class SeverityBreakdown(BaseModel):
    Critical: int = 0
    High: int = 0
    Medium: int = 0
    Low: int = 0
    Unknown: int = 0


class SecurityFinding(BaseModel):
    timestamp: _dt.datetime
    description: str
    cve_id: Optional[str] = None
    solution: List[str]


class DeviceReport(BaseModel):
    device_name: str
    ip_address: Optional[str] = None
    last_scan: Optional[_dt.datetime] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    total_issues: int
    cve_count: int
    high_severity_issues: int
    severity_breakdown: SeverityBreakdown
    security_findings: List[SecurityFinding]


class ReportResponse(BaseModel):
    devices: List[DeviceReport]


###############################################################################
# FastAPI application
###############################################################################

app = FastAPI(title="Wazuh Report API", version="1.0.0", docs_url="/docs", redoc_url="/redoc")

# ────────────────────────────────────────────────────────────── CORS (edit) ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update in production!
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────── Lifespan hooks ──
@app.on_event("startup")
async def _startup() -> None:  # pragma: no cover
    app.state.settings = get_settings()
    app.state.client = WazuhClient(app.state.settings)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)8s | %(message)s")
    logging.info("Wazuh Report API initialised → %s", app.state.settings.WAZUH_API_URL)


@app.on_event("shutdown")
async def _shutdown() -> None:  # pragma: no cover
    await app.state.client.close()
    logging.info("HTTP client closed – shutdown complete")


###############################################################################
# Dependency injection helpers
###############################################################################

async def get_client() -> WazuhClient:
    return app.state.client  # type: ignore[attr-defined]


###############################################################################
# Utility – Build report for a single agent
###############################################################################

async def _agent_report(agent: dict, client: WazuhClient) -> DeviceReport:
    agent_id = agent["id"]

    # 1️⃣ Fetch vulnerabilities (max 5 000 per agent by default)
    vulns_data = await client.get(f"/vulnerability/{agent_id}?limit=5000&sort=severity")
    vulns = vulns_data.get("data", {}).get("affected_items", [])

    # 2️⃣ Aggregate severity counts & findings
    sev_map = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    cve_ids: set[str] = set()
    findings: List[SecurityFinding] = []

    for v in vulns:
        sev = v.get("severity", "Unknown").capitalize()
        sev = sev if sev in sev_map else "Unknown"
        sev_map[sev] += 1
        cve = v.get("cve")
        if cve:
            cve_ids.add(cve)
        findings.append(
            SecurityFinding(
                timestamp=_dt.datetime.fromisoformat(v.get("detect_time").replace("Z", "+00:00")),
                description=v.get("title"),
                cve_id=cve,
                solution=v.get("references", []),
            )
        )

    # 3️⃣ Transform agent metadata
    last_scan_ms = agent.get("lastKeepAlive")
    last_scan_dt = _dt.datetime.fromtimestamp(last_scan_ms / 1000.0, tz=_dt.timezone.utc) if last_scan_ms else None

    return DeviceReport(
        device_name=agent.get("name"),
        ip_address=agent.get("ip"),
        last_scan=last_scan_dt,
        os_name=agent.get("os", {}).get("name"),
        os_version=agent.get("os", {}).get("version"),
        total_issues=len(vulns),
        cve_count=len(cve_ids),
        high_severity_issues=sev_map["High"],
        severity_breakdown=SeverityBreakdown(**sev_map),
        security_findings=findings,
    )


###############################################################################
# Public endpoints
###############################################################################

@app.get("/report", response_model=ReportResponse, summary="Full report for all agents")
async def get_report(
    limit: int = Query(100, ge=1, le=10000, description="Maximum number of agents to fetch"),
    client: WazuhClient = Depends(get_client),
):
    """Return an aggregated report for up to *limit* agents."""

    # 1️⃣ Fetch agents list
    agents_resp = await client.get(f"/agents?limit={limit}")
    agents = agents_resp["data"]["affected_items"]

    # 2️⃣ Build reports in parallel (but throttled)
    semaphore = asyncio.Semaphore(20)  # avoid flooding the manager

    async def _worker(a: dict):
        async with semaphore:
            return await _agent_report(a, client)

    devices: List[DeviceReport] = await asyncio.gather(*(_worker(a) for a in agents))

    return ReportResponse(devices=devices)


@app.get(
    "/report/{agent_id}",
    response_model=DeviceReport,
    summary="Report for a single agent",
    responses={404: {"description": "Agent not found"}},
)
async def get_single_report(agent_id: str, client: WazuhClient = Depends(get_client)):
    """Return a detailed report for a **single** agent (by ID)."""
    try:
        agent_resp = await client.get(f"/agents/{agent_id}")
    except HTTPException as ex:
        if ex.status_code == 404:
            raise HTTPException(404, "Agent not found") from ex
        raise

    agent = agent_resp["data"]["affected_items"][0]
    return await _agent_report(agent, client)
