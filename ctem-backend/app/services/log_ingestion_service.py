from app.db.supabase_client import get_client
from app.services import alert_service

RULE_SEVERITY_TO_ALERT = ["high", "critical"]


def ingest_event(source, asset_id, event_type, severity, summary, occurred_at=None):
    client = get_client()
    row = {
        "source": source,
        "asset_id": asset_id,
        "event_type": event_type,
        "severity": severity,
        "summary": summary,
    }
    if occurred_at:
        row["occurred_at"] = occurred_at

    result = client.table("security_events").insert(row).execute()
    event = result.data[0]

    if severity in RULE_SEVERITY_TO_ALERT:
        alert_service.create_alert(
            alert_type="log_severity",
            title=f"{severity} severity event: {event_type}",
            description=summary,
            severity=severity,
            asset_id=asset_id,
            source_reference_id=event["id"],
        )

    return event


def list_events(asset_id=None, severity=None, limit=100):
    client = get_client()
    query = client.table("security_events").select("*").order("occurred_at", desc=True).limit(limit)
    if asset_id:
        query = query.eq("asset_id", asset_id)
    if severity:
        query = query.eq("severity", severity)
    return query.execute().data
