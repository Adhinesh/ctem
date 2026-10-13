from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, Header
from app.schemas.scans import ScanCreateRequest
from app.services import scan_service, target_validation

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("")
async def create_scan(request: ScanCreateRequest, background_tasks: BackgroundTasks, x_tenant_id: Optional[str] = Header(default=None)):
    try:
        clean_target = target_validation.validate_target(request.target, request.target_type)
    except target_validation.ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not target_validation.check_rate_limit(x_tenant_id):
        raise HTTPException(status_code=429, detail="scan submission rate limit exceeded")

    existing = scan_service.find_existing_scan(clean_target)
    if existing and not request.force_new:
        return {"existing": True, "scan": existing}

    scan = scan_service.create_scan(clean_target, request.target_type, request.labels, tenant_id=x_tenant_id)
    background_tasks.add_task(scan_service.run_scan_pipeline, scan["scan_id"], clean_target, request.target_type)

    return {"existing": False, "scan": scan}


@router.get("/{scan_id}")
async def get_scan_status(scan_id: str):
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@router.get("/{scan_id}/assets")
async def get_scan_assets(scan_id: str):
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return {"scan_id": scan_id, "assets": scan_service.get_scan_assets(scan_id)}


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    scan_service.cancel_scan(scan_id)
    return {"status": "cancelled", "scan_id": scan_id}


@router.post("/{scan_id}/rescan")
async def rescan_target(scan_id: str, background_tasks: BackgroundTasks):
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")

    if scan.get("status") in ("queued", "running", "ingesting", "scoring"):
        raise HTTPException(status_code=400, detail=f"Scan is currently active ({scan.get('status')})")

    scan_service.reset_scan_for_rerun(scan_id)
    background_tasks.add_task(scan_service.run_scan_pipeline, scan_id, scan["target"], scan["target_type"])
    return {"status": "queued", "scan_id": scan_id, "rescan": True}


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    scan_service.delete_scan(scan_id)
    return {"status": "deleted", "scan_id": scan_id}


@router.get("")
async def get_scan_history(target: str = None, x_tenant_id: Optional[str] = Header(default=None)):
    return {"history": scan_service.get_scan_history(target=target, tenant_id=x_tenant_id)}
