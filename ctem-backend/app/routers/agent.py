from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.db.supabase_client import get_client
from app.services import alert_service, change_detection_service

router = APIRouter(prefix="/agent", tags=["agent"])


class AgentRegisterRequest(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    asset_type: str = "endpoint"
    zone: str = "internal"
    criticality: str = "medium"
    agent_version: str = "1.0.0"
    metadata: Optional[Dict[str, Any]] = None


class AgentHeartbeatRequest(BaseModel):
    asset_id: str
    hostname: Optional[str] = None
    metrics: Dict[str, Any] = {}
    listening_ports: Optional[List[Dict[str, Any]]] = None
    agent_version: Optional[str] = "1.0.0"


@router.post("/register")
async def register_agent(req: AgentRegisterRequest):
    try:
        client = get_client()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Database initialization error: {str(e)}. Check SUPABASE_URL and SUPABASE_KEY in .env.",
        )

    if not req.hostname and not req.ip_address:
        raise HTTPException(status_code=400, detail="Hostname or IP address required for agent registration")

    valid_types = ["endpoint", "server", "vps", "firewall", "computer", "laptop", "network_segment", "cloud_resource"]
    asset_type = req.asset_type if req.asset_type in valid_types else "endpoint"
    zone = req.zone if req.zone in ["internal", "external"] else "internal"
    criticality = req.criticality if req.criticality in ["low", "medium", "high", "critical"] else "medium"

    now_iso = datetime.utcnow().isoformat()

    try:
        # Check if asset already exists by hostname or IP
        existing = None
        if req.hostname:
            existing = client.table("assets").select("*").eq("hostname", req.hostname).limit(1).execute()
        if (not existing or not existing.data) and req.ip_address:
            existing = client.table("assets").select("*").eq("ip_address", req.ip_address).limit(1).execute()

        if existing and existing.data:
            asset_id = existing.data[0]["id"]
            update_data = {
                "asset_status": "confirmed",
                "asset_confirmed": True,
                "zone": zone,
                "criticality": criticality,
                "asset_type": asset_type,
                "declared_by": f"ctem-agent v{req.agent_version}",
                "declared_at": now_iso,
                "updated_at": now_iso,
            }
            if req.ip_address and not existing.data[0].get("ip_address"):
                update_data["ip_address"] = req.ip_address
            if req.hostname and not existing.data[0].get("hostname"):
                update_data["hostname"] = req.hostname

            try:
                client.table("assets").update(update_data).eq("id", asset_id).execute()
            except Exception:
                update_data.pop("ip_address", None)
                client.table("assets").update(update_data).eq("id", asset_id).execute()

            # Log registration event
            try:
                client.table("security_events").insert({
                    "source": "ctem_agent",
                    "asset_id": asset_id,
                    "event_type": "agent_connected",
                    "severity": "low",
                    "summary": f"CTEM Agent v{req.agent_version} connected and synced host '{req.hostname or req.ip_address}'",
                    "occurred_at": now_iso,
                }).execute()
            except Exception:
                pass

            return {
                "status": "connected",
                "asset_id": asset_id,
                "hostname": req.hostname,
                "ip_address": req.ip_address,
                "is_new": False,
                "config": {
                    "heartbeat_interval": 30,
                    "port_scan_interval": 60,
                    "log_monitoring": True,
                    "ueba_monitoring": True,
                }
            }

        # Insert new asset
        row = {
            "hostname": req.hostname,
            "ip_address": req.ip_address,
            "asset_type": asset_type,
            "zone": zone,
            "criticality": criticality,
            "asset_status": "confirmed",
            "asset_confirmed": True,
            "declared_by": f"ctem-agent v{req.agent_version}",
            "declared_at": now_iso,
            "created_at": now_iso,
            "updated_at": now_iso,
        }
        result = client.table("assets").insert(row).execute()
        new_asset = result.data[0]
        asset_id = new_asset["id"]

        # Log registration event
        try:
            client.table("security_events").insert({
                "source": "ctem_agent",
                "asset_id": asset_id,
                "event_type": "agent_registered",
                "severity": "low",
                "summary": f"New asset registered by CTEM Agent v{req.agent_version}: '{req.hostname or req.ip_address}' ({asset_type})",
                "occurred_at": now_iso,
            }).execute()
        except Exception:
            pass

        return {
            "status": "registered",
            "asset_id": asset_id,
            "hostname": req.hostname,
            "ip_address": req.ip_address,
            "is_new": True,
            "config": {
                "heartbeat_interval": 30,
                "port_scan_interval": 60,
                "log_monitoring": True,
                "ueba_monitoring": True,
            }
        }
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Database error during agent registration: {str(exc)}",
        )


@router.post("/heartbeat")
async def agent_heartbeat(req: AgentHeartbeatRequest):
    client = get_client()
    now_iso = datetime.utcnow().isoformat()

    # Verify asset exists
    asset_res = client.table("assets").select("id, hostname, ip_address").eq("id", req.asset_id).limit(1).execute()
    if not asset_res.data:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Update asset last seen timestamp
    client.table("assets").update({"updated_at": now_iso}).eq("id", req.asset_id).execute()

    # Handle listening ports and drift detection
    port_changes = []
    if req.listening_ports is not None:
        existing_ports_res = client.table("open_ports").select("*").eq("asset_id", req.asset_id).execute()
        existing_ports = existing_ports_res.data or []
        existing_map = {f"{p.get('port')}/{p.get('protocol', 'tcp')}": p for p in existing_ports}

        # Filter out OS-assigned dynamic/ephemeral ports (RPC 49152+)
        incoming_ports = [
            p for p in req.listening_ports
            if p.get("port") and not change_detection_service._is_ephemeral(p.get("port"))
        ]

        if incoming_ports:
            agent_rows = []
            for p in incoming_ports:
                port_num = str(p.get("port"))
                proto = str(p.get("protocol", "tcp")).lower()
                agent_rows.append({
                    "asset_id": req.asset_id,
                    "port": port_num,
                    "protocol": proto,
                    "service": p.get("service") or "unknown",
                    "product": p.get("product"),
                    "version": p.get("version"),
                })
            try:
                client.table("open_ports").upsert(agent_rows, on_conflict="asset_id,port,protocol").execute()
            except Exception:
                pass

    # Check for extreme resource exhaustion alerts
    cpu = req.metrics.get("cpu_percent")
    mem = req.metrics.get("memory_percent")
    disk = req.metrics.get("disk_percent")

    if disk and disk >= 95:
        client.table("security_events").insert({
            "source": "ctem_agent",
            "asset_id": req.asset_id,
            "event_type": "disk_exhaustion_critical",
            "severity": "critical",
            "summary": f"Critical Disk Usage Alert on {req.hostname or req.asset_id}: {disk}% utilized",
            "occurred_at": now_iso,
        }).execute()
        alert_service.create_alert(
            alert_type="log_severity",
            title=f"Critical Disk Usage on {req.hostname or 'Asset'}",
            description=f"Host filesystem is {disk}% full. Potential denial of service risk.",
            severity="critical",
            asset_id=req.asset_id,
        )
    elif cpu and cpu >= 95:
        client.table("security_events").insert({
            "source": "ctem_agent",
            "asset_id": req.asset_id,
            "event_type": "cpu_spike_critical",
            "severity": "high",
            "summary": f"High CPU Utilization on {req.hostname or req.asset_id}: {cpu}% sustained",
            "occurred_at": now_iso,
        }).execute()
        alert_service.create_alert(
            alert_type="log_severity",
            title=f"CPU Spike Anomaly on {req.hostname or 'Asset'}",
            description=f"CPU usage sustained at {cpu}%. May indicate cryptominer or denial of service.",
            severity="high",
            asset_id=req.asset_id,
        )

    # Ingest routine heartbeat telemetry into security_events
    summary_parts = []
    if cpu is not None:
        summary_parts.append(f"CPU: {cpu}%")
    if mem is not None:
        summary_parts.append(f"RAM: {mem}%")
    if disk is not None:
        summary_parts.append(f"Disk: {disk}%")
    ports_count = len(req.listening_ports) if req.listening_ports is not None else 0
    summary_parts.append(f"Listening Ports: {ports_count}")

    client.table("security_events").insert({
        "source": "ctem_agent",
        "asset_id": req.asset_id,
        "event_type": "agent_heartbeat",
        "severity": "low",
        "summary": f"Agent Heartbeat [{req.hostname or req.asset_id}] - {', '.join(summary_parts)}",
        "occurred_at": now_iso,
    }).execute()

    return {
        "status": "ok",
        "asset_id": req.asset_id,
        "server_time": now_iso,
        "port_changes_detected": port_changes,
    }


@router.get("/status/{asset_id}")
async def get_agent_status(asset_id: str):
    client = get_client()
    asset_res = client.table("assets").select("*").eq("id", asset_id).limit(1).execute()
    if not asset_res.data:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset = asset_res.data[0]
    ports_res = client.table("open_ports").select("*").eq("asset_id", asset_id).execute()
    recent_events = (
        client.table("security_events")
        .select("*")
        .eq("asset_id", asset_id)
        .order("occurred_at", desc=True)
        .limit(10)
        .execute()
    )
    alerts_res = client.table("alerts").select("*").eq("asset_id", asset_id).eq("status", "open").execute()

    return {
        "asset": asset,
        "open_ports": ports_res.data or [],
        "open_alerts_count": len(alerts_res.data or []),
        "recent_events": recent_events.data or [],
    }
