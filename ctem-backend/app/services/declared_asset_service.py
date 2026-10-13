from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from app.db.supabase_client import get_client

VALID_ASSET_TYPES = ["endpoint", "server", "vps", "firewall", "computer", "laptop", "network_segment", "cloud_resource"]
VALID_ZONES = ["internal", "external"]
VALID_CRITICALITY = ["low", "medium", "high", "critical"]


class DeclaredAssetInput(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: str
    zone: str
    criticality: str = "low"


class DeclaredAssetBatchRequest(BaseModel):
    assets: List[DeclaredAssetInput]
    declared_by: str


def register_declared_assets(request: DeclaredAssetBatchRequest):
    client = get_client()
    created = []

    for item in request.assets:
        if item.asset_type not in VALID_ASSET_TYPES:
            raise ValueError(f"invalid asset_type: {item.asset_type}")
        if item.zone not in VALID_ZONES:
            raise ValueError(f"invalid zone: {item.zone}")
        if item.criticality not in VALID_CRITICALITY:
            raise ValueError(f"invalid criticality: {item.criticality}")
        if not item.hostname and not item.ip_address:
            raise ValueError("each declared asset needs a hostname or ip_address")

        existing = None
        if item.hostname:
            existing = client.table("assets").select("id").eq("hostname", item.hostname).limit(1).execute()
        elif item.ip_address:
            existing = client.table("assets").select("id").eq("ip_address", item.ip_address).limit(1).execute()

        if existing and existing.data:
            asset_id = existing.data[0]["id"]
            client.table("assets").update({
                "asset_status": "declared",
                "asset_confirmed": True,
                "zone": item.zone,
                "criticality": item.criticality,
                "asset_type": item.asset_type,
                "declared_by": request.declared_by,
                "declared_at": datetime.utcnow().isoformat(),
            }).eq("id", asset_id).execute()
            created.append({"id": asset_id, "hostname": item.hostname, "ip_address": item.ip_address, "updated": True})
            continue

        row = {
            "hostname": item.hostname,
            "ip_address": item.ip_address,
            "asset_type": item.asset_type,
            "zone": item.zone,
            "criticality": item.criticality,
            "asset_status": "declared",
            "asset_confirmed": True,
            "declared_by": request.declared_by,
            "declared_at": datetime.utcnow().isoformat(),
        }
        result = client.table("assets").insert(row).execute()
        created.append({"id": result.data[0]["id"], "hostname": item.hostname, "ip_address": item.ip_address, "updated": False})

    return created
