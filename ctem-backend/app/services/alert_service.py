from datetime import datetime, timedelta, timezone
from app.db.supabase_client import get_client


ALERT_TYPE_MAPPING = {
    "endpoint_change": "asset_change",
    "hardware_change": "asset_change",
    "log_rule": "log_severity",
    "ueba": "ueba_anomaly",
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Identical alerts (same type + title + asset) raised within this window are merged
# into the existing open alert instead of creating a new row. This stops a single
# incident (e.g. 7 failed logins, a flapping port) from flooding the Alerts view.
DEDUP_WINDOW_MINUTES = 30


def _find_open_duplicate(client, normalized_type, title, asset_id):
    window_start = (datetime.now(timezone.utc) - timedelta(minutes=DEDUP_WINDOW_MINUTES)).isoformat()
    query = (
        client.table("alerts")
        .select("*")
        .eq("alert_type", normalized_type)
        .eq("title", title)
        .in_("status", ["open", "acknowledged"])
        .gte("updated_at", window_start)
        .order("updated_at", desc=True)
        .limit(1)
    )
    query = query.eq("asset_id", asset_id) if asset_id else query.is_("asset_id", "null")
    result = query.execute()
    return result.data[0] if result.data else None


def create_alert(alert_type, title, description, severity, asset_id=None, source_reference_id=None, source_event_id=None):
    client = get_client()
    normalized_type = ALERT_TYPE_MAPPING.get(alert_type, alert_type)
    ref_id = source_reference_id or source_event_id

    # Deduplicate: refresh the existing open alert rather than inserting a new one
    try:
        existing = _find_open_duplicate(client, normalized_type, title, asset_id)
    except Exception:
        existing = None

    if existing:
        update = {
            "description": description,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        # Escalate severity if the repeated occurrence is more severe
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(existing.get("severity"), 0):
            update["severity"] = severity
        try:
            client.table("alerts").update(update).eq("id", existing["id"]).execute()
            existing.update(update)
            existing["deduplicated"] = True
            return existing
        except Exception:
            pass

    row = {
        "alert_type": normalized_type,
        "title": title,
        "description": description,
        "severity": severity,
        "asset_id": asset_id,
        "source_reference_id": ref_id,
    }
    result = client.table("alerts").insert(row).execute()
    return result.data[0] if result.data else row


def list_alerts(status=None, severity=None, alert_type=None, asset_id=None):
    client = get_client()
    query = client.table("alerts").select("*").order("created_at", desc=True)
    if status:
        query = query.eq("status", status)
    if severity:
        query = query.eq("severity", severity)
    if alert_type:
        query = query.eq("alert_type", alert_type)
    if asset_id:
        query = query.eq("asset_id", asset_id)
    return query.execute().data


def acknowledge_alert(alert_id):
    client = get_client()
    client.table("alerts").update({"status": "acknowledged"}).eq("id", alert_id).execute()


def resolve_alert(alert_id):
    client = get_client()
    client.table("alerts").update({"status": "resolved"}).eq("id", alert_id).execute()
