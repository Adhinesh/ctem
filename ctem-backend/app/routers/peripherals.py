from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.services import peripheral_service

router = APIRouter(prefix="/peripherals", tags=["peripherals"])


class PeripheralRegisterRequest(BaseModel):
    device_type: str
    serial_number: Optional[str] = None
    device_identifier: Optional[str] = None
    label: Optional[str] = None
    associated_asset_id: Optional[str] = None
    ip_address: Optional[str] = None
    authorized: bool = False
    authorized_by: Optional[str] = None


class PeripheralAuthorizeRequest(BaseModel):
    authorized: bool
    authorized_by: Optional[str] = None


class PeripheralCheckRequest(BaseModel):
    serial_number: Optional[str] = None
    device_identifier: Optional[str] = None


DEVICE_TYPES = ["router", "hard_drive", "pendrive", "usb_storage", "other"]


@router.post("")
async def register_peripheral(request: PeripheralRegisterRequest):
    if request.device_type not in DEVICE_TYPES:
        raise HTTPException(status_code=400, detail=f"device_type must be one of {DEVICE_TYPES}")
    if not request.serial_number and not request.device_identifier:
        raise HTTPException(status_code=400, detail="serial_number or device_identifier is required")

    peripheral = peripheral_service.register_peripheral(
        device_type=request.device_type,
        serial_number=request.serial_number,
        device_identifier=request.device_identifier,
        label=request.label,
        associated_asset_id=request.associated_asset_id,
        ip_address=request.ip_address,
        authorized=request.authorized,
        authorized_by=request.authorized_by,
    )
    return peripheral


@router.get("")
async def list_peripherals(authorized: bool = None, device_type: str = None):
    return {"peripherals": peripheral_service.list_peripherals(authorized=authorized, device_type=device_type)}


@router.post("/{peripheral_id}/authorize")
async def authorize_peripheral(peripheral_id: str, request: PeripheralAuthorizeRequest):
    peripheral_service.set_authorization(peripheral_id, request.authorized, request.authorized_by)
    return {"peripheral_id": peripheral_id, "authorized": request.authorized}


@router.post("/check")
async def check_peripheral(request: PeripheralCheckRequest):
    if not request.serial_number and not request.device_identifier:
        raise HTTPException(status_code=400, detail="serial_number or device_identifier is required")
    return peripheral_service.check_authorization(
        serial_number=request.serial_number,
        device_identifier=request.device_identifier,
    )


@router.delete("/{peripheral_id}")
async def delete_peripheral(peripheral_id: str):
    peripheral_service.delete_peripheral(peripheral_id)
    return {"peripheral_id": peripheral_id, "deleted": True}


@router.post("/{peripheral_id}/check-reachability")
async def check_peripheral_reachability(peripheral_id: str):
    return await peripheral_service.check_peripheral_reachability(peripheral_id)
