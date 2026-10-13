from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services import log_ingestion_service

router = APIRouter(prefix="/logs", tags=["logs"])


class LogEventRequest(BaseModel):
    source: str = "security_onion"
    asset_id: Optional[str] = None
    event_type: str
    severity: str = "low"
    summary: Optional[str] = None
    occurred_at: Optional[str] = None


@router.post("/events")
async def ingest_log_event(request: LogEventRequest):
    event = log_ingestion_service.ingest_event(
        source=request.source,
        asset_id=request.asset_id,
        event_type=request.event_type,
        severity=request.severity,
        summary=request.summary,
        occurred_at=request.occurred_at,
    )
    return event


@router.get("/events")
async def list_log_events(asset_id: str = None, severity: str = None):
    return {"events": log_ingestion_service.list_events(asset_id=asset_id, severity=severity)}
