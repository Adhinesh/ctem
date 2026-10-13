from app.db.supabase_client import get_client
from app.services import alert_service

# OS-assigned dynamic/ephemeral listeners (Windows RPC 49664+, app sockets) churn
# constantly and are not meaningful exposure changes on their own.
EPHEMERAL_PORT_START = 49152


def _is_ephemeral(port):
    try:
        return int(port) >= EPHEMERAL_PORT_START
    except (TypeError, ValueError):
        return False


def detect_port_change(asset_id, previous, current, is_first_scan=False):
    client = get_client()

    if previous is None and current is not None:
        port_label = f"{current.get('port')}/{current.get('protocol')}"
        _log_change(client, asset_id, "port_opened", None, port_label)
        if is_first_scan or _is_ephemeral(current.get("port")):
            return
        alert_service.create_alert(
            alert_type="asset_change",
            title=f"New port opened on asset: {port_label}",
            description=f"Port {port_label} ({current.get('service')}) newly detected",
            severity="medium",
            asset_id=asset_id,
        )
        return

    if previous is not None and current is None:
        if is_first_scan:
            return
        # Closures reduce attack surface: record in the change log, but don't alert
        _log_change(client, asset_id, "port_closed", f"{previous.get('port')}/{previous.get('protocol')}", None)
        return

    if previous is None or current is None:
        return

    if previous.get("version") != current.get("version"):
        _log_change(client, asset_id, "version_changed", previous.get("version"), current.get("version"))
        alert_service.create_alert(
            alert_type="asset_change",
            title=f"Service version changed",
            description=f"{current.get('product')} on port {current.get('port')} changed from {previous.get('version')} to {current.get('version')}",
            severity="low",
            asset_id=asset_id,
        )
        return

    if previous.get("service") != current.get("service"):
        _log_change(client, asset_id, "service_changed", previous.get("service"), current.get("service"))
        alert_service.create_alert(
            alert_type="asset_change",
            title=f"Service changed on existing port",
            description=f"Port {current.get('port')} service changed from {previous.get('service')} to {current.get('service')}",
            severity="medium",
            asset_id=asset_id,
        )


def _log_change(client, asset_id, change_type, previous_value, new_value):
    client.table("asset_change_log").insert({
        "asset_id": asset_id,
        "change_type": change_type,
        "previous_value": previous_value,
        "new_value": new_value,
    }).execute()


def list_changes(asset_id=None, limit=100):
    client = get_client()
    query = client.table("asset_change_log").select("*").order("detected_at", desc=True).limit(limit)
    if asset_id:
        query = query.eq("asset_id", asset_id)
    return query.execute().data
