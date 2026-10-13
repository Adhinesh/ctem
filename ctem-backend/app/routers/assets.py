from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.db.supabase_client import get_client
from app.services import ingestion_runner, declared_asset_service
from app.services.declared_asset_service import DeclaredAssetBatchRequest

router = APIRouter(prefix="/assets", tags=["assets"])


class AssetEditRequest(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: Optional[str] = None
    zone: Optional[str] = None
    criticality: Optional[str] = None


@router.post("/declared")
async def declare_assets(request: DeclaredAssetBatchRequest):
    try:
        created = declared_asset_service.register_declared_assets(request)
        from app.services import scoring_runner
        new_ids = [a["id"] for a in created if isinstance(a, dict) and "id" in a]
        if new_ids:
            try:
                await scoring_runner.score_assets(new_ids)
            except Exception:
                pass
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"assets": created}


@router.get("")
async def list_assets(asset_status: str = None, zone: str = None, q: str = None):
    client = get_client()
    query = client.table("assets").select("*").order("created_at", desc=True)
    if asset_status:
        query = query.eq("asset_status", asset_status)
    if zone:
        query = query.eq("zone", zone)
    result = query.execute()
    assets = result.data or []
    if q:
        q_lower = q.lower()
        assets = [
            a for a in assets
            if (a.get("hostname") and q_lower in a["hostname"].lower())
            or (a.get("ip_address") and q_lower in a["ip_address"].lower())
            or (a.get("asset_type") and q_lower in a["asset_type"].lower())
        ]
    return {"assets": assets}


@router.get("/{asset_id}")
async def get_asset(asset_id: str):
    client = get_client()
    result = client.table("assets").select("*").eq("id", asset_id).limit(1).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="asset not found")
    asset = result.data[0]
    ports_res = client.table("open_ports").select("*").eq("asset_id", asset_id).execute()
    asset["open_ports"] = ports_res.data or []
    return asset


@router.post("/{asset_id}/confirm")
async def confirm_asset(asset_id: str):
    ingestion_runner.confirm_asset(asset_id)
    from app.services import scoring_runner
    try:
        await scoring_runner.score_assets([asset_id])
    except Exception:
        pass
    return {"asset_id": asset_id, "asset_status": "confirmed"}


@router.patch("/{asset_id}")
async def edit_asset(asset_id: str, request: AssetEditRequest):
    fields = {k: v for k, v in request.dict().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="no fields to update")
    ingestion_runner.edit_asset(asset_id, fields)
    from app.services import scoring_runner
    try:
        await scoring_runner.score_assets([asset_id])
    except Exception:
        pass
    return {"asset_id": asset_id, "updated_fields": fields}


@router.get("/{asset_id}/changes")
async def get_asset_changes(asset_id: str):
    from app.services import change_detection_service
    return {"asset_id": asset_id, "changes": change_detection_service.list_changes(asset_id=asset_id)}


@router.delete("/{asset_id}")
async def delete_asset(asset_id: str):
    ingestion_runner.delete_asset(asset_id)
    return {"asset_id": asset_id, "deleted": True}


@router.get("/{asset_id}/blast-radius")
async def get_asset_blast_radius_alias(asset_id: str, mode: Optional[str] = "combined"):
    from app.services import blast_radius_service
    client = get_client()
    result = blast_radius_service.get_asset_blast_radius(client, asset_id, mode=mode)
    if not result:
        raise HTTPException(status_code=404, detail="asset not found")
    return result


@router.get("/{asset_id}/dependencies")
async def get_asset_dependencies_alias(asset_id: str):
    from app.services import blast_radius_service
    client = get_client()
    return {"dependencies": blast_radius_service.list_asset_dependencies(client, asset_id=asset_id)}

