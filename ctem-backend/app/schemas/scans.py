from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class ScanCreateRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    target_type: str
    labels: Optional[dict] = None
    force_new: bool = False


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    target_type: str
    status: str
    labels: dict
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime
    error_message: Optional[str]


class ScanHistoryEntry(BaseModel):
    scan_id: str
    target: str
    status: str
    created_at: datetime
    finished_at: Optional[datetime]


class ScanAssetEntry(BaseModel):
    asset_id: str
    hostname: Optional[str]
    ip_address: Optional[str]
    zone: Optional[str]
    asset_status: Optional[str]
