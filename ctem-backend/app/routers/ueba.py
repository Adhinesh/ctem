from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services import ueba_service

router = APIRouter(prefix="/ueba", tags=["ueba"])


class UebaEventRequest(BaseModel):
    username: str
    event_type: str
    source_ip: Optional[str] = None
    occurred_at: Optional[str] = None
    asset_id: Optional[str] = None
    hostname: Optional[str] = None


@router.post("/events")
async def record_event(request: UebaEventRequest):
    event = ueba_service.record_event(
        username=request.username,
        event_type=request.event_type,
        source_ip=request.source_ip,
        occurred_at=request.occurred_at,
        asset_id=request.asset_id,
        hostname=request.hostname,
    )
    return event


@router.get("/events")
async def list_events(username: str = None, event_type: str = None):
    return {"events": ueba_service.list_events(username=username, event_type=event_type)}
