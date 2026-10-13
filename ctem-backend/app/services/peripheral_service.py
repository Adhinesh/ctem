import asyncio
from datetime import datetime
from app.db.supabase_client import get_client


def register_peripheral(device_type, serial_number, device_identifier, label, associated_asset_id, ip_address, authorized, authorized_by):
    client = get_client()
    row = {
        "device_type": device_type,
        "serial_number": serial_number,
        "device_identifier": device_identifier,
        "label": label,
        "associated_asset_id": associated_asset_id,
        "ip_address": ip_address,
        "authorized": authorized,
        "authorized_by": authorized_by if authorized else None,
        "authorized_at": datetime.utcnow().isoformat() if authorized else None,
    }
    result = client.table("peripheral_devices").insert(row).execute()
    return result.data[0]


def list_peripherals(authorized=None, device_type=None):
    client = get_client()
    query = client.table("peripheral_devices").select("*")
    if authorized is not None:
        query = query.eq("authorized", authorized)
    if device_type:
        query = query.eq("device_type", device_type)
    return query.execute().data


def set_authorization(peripheral_id, authorized, authorized_by):
    client = get_client()
    update = {
        "authorized": authorized,
        "authorized_by": authorized_by if authorized else None,
        "authorized_at": datetime.utcnow().isoformat() if authorized else None,
    }
    client.table("peripheral_devices").update(update).eq("id", peripheral_id).execute()


def delete_peripheral(peripheral_id):
    client = get_client()
    client.table("peripheral_devices").delete().eq("id", peripheral_id).execute()


def check_authorization(serial_number=None, device_identifier=None):
    from app.services import alert_service
    client = get_client()
    query = client.table("peripheral_devices").select("*")

    if serial_number:
        query = query.eq("serial_number", serial_number)
    elif device_identifier:
        query = query.eq("device_identifier", device_identifier)
    else:
        return _log_and_return(client, None, serial_number, device_identifier, "unknown", "unauthorized")

    result = query.limit(1).execute()

    if not result.data:
        # Unknown device not in allowlist: classify as UNAUTHORIZED and generate security alert
        identifier_str = serial_number or device_identifier or "Unknown Device"
        try:
            alert_service.create_alert(
                alert_type="peripheral_unauthorized",
                title="Unauthorized unknown peripheral connected",
                description=f"Hardware device '{identifier_str}' attempted connection. Device is not in enterprise allowlist; access blocked.",
                severity="high",
            )
        except Exception:
            pass
        return _log_and_return(client, None, serial_number, device_identifier, "unknown", "unauthorized")

    peripheral = result.data[0]
    result_status = "authorized" if peripheral["authorized"] else "unauthorized"

    if result_status == "unauthorized":
        identifier_str = serial_number or device_identifier or peripheral.get("label") or "Blocked Device"
        try:
            alert_service.create_alert(
                alert_type="peripheral_unauthorized",
                title=f"Unauthorized {peripheral.get('device_type', 'peripheral')} connected",
                description=f"Hardware device '{identifier_str}' ({peripheral.get('label') or 'unlabeled'}) is marked as blocked in allowlist. Access denied.",
                severity="high",
                asset_id=peripheral.get("associated_asset_id"),
            )
        except Exception:
            pass

    return _log_and_return(client, peripheral["id"], serial_number, device_identifier, peripheral.get("device_type"), result_status)


def _log_and_return(client, peripheral_id, serial_number, device_identifier, device_type, result_status):
    event = {
        "peripheral_id": peripheral_id,
        "serial_number": serial_number,
        "device_identifier": device_identifier,
        "device_type": device_type,
        "result": result_status,
    }
    client.table("peripheral_check_events").insert(event).execute()
    return {"peripheral_id": peripheral_id, "result": result_status}


async def check_reachability(ip_address, port=80, timeout=3.0):
    try:
        conn = asyncio.open_connection(ip_address, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def check_peripheral_reachability(peripheral_id):
    client = get_client()
    result = client.table("peripheral_devices").select("*").eq("id", peripheral_id).limit(1).execute()
    if not result.data:
        return {"peripheral_id": peripheral_id, "result": "unknown"}

    peripheral = result.data[0]
    ip_address = peripheral.get("ip_address")
    if not ip_address:
        return _log_and_return(client, peripheral_id, peripheral.get("serial_number"), peripheral.get("device_identifier"), peripheral.get("device_type"), "unknown")

    reachable = await check_reachability(ip_address)
    result_status = "reachable" if reachable else "unreachable"
    return _log_and_return(client, peripheral_id, peripheral.get("serial_number"), peripheral.get("device_identifier"), peripheral.get("device_type"), result_status)
