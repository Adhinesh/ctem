from fastapi import APIRouter
from app.services import alert_service

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(status: str = None, severity: str = None, alert_type: str = None, asset_id: str = None):
    return {"alerts": alert_service.list_alerts(status=status, severity=severity, alert_type=alert_type, asset_id=asset_id)}


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    alert_service.acknowledge_alert(alert_id)
    return {"alert_id": alert_id, "status": "acknowledged"}


@router.post("/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    alert_service.resolve_alert(alert_id)
    return {"alert_id": alert_id, "status": "resolved"}
