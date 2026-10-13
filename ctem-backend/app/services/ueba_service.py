import re
from datetime import datetime, timedelta, timezone
from app.db.supabase_client import get_client
from app.services import alert_service

FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_CRITICAL_THRESHOLD = 10
FAILED_LOGIN_WINDOW_MINUTES = 15
OFF_HOURS_START = 22
OFF_HOURS_END = 6

# Windows built-in / service identities that generate constant logon noise
# (Desktop Window Manager, User-Mode Font Driver, machine accounts, services).
_SYSTEM_ACCOUNT_PATTERN = re.compile(r"^(DWM|UMFD)-\d+$", re.IGNORECASE)
_SYSTEM_ACCOUNT_NAMES = {
    "", "-", "system", "local service", "network service", "anonymous logon",
    "localsystem", "defaultaccount", "wdagutilityaccount",
}
_LOCAL_SOURCE_IPS = {"", "-", "127.0.0.1", "::1", "0.0.0.0", "localhost"}


def is_system_account(username):
    name = (username or "").strip()
    if name.lower() in _SYSTEM_ACCOUNT_NAMES:
        return True
    if name.endswith("$"):  # machine accounts, e.g. DESKTOP-B082BGD$
        return True
    return bool(_SYSTEM_ACCOUNT_PATTERN.match(name))


def record_event(username, event_type, source_ip, occurred_at=None, asset_id=None, hostname=None):
    if is_system_account(username):
        return {"ignored": True, "reason": "system_account", "username": username}

    client = get_client()
    row = {
        "username": username,
        "event_type": event_type,
        "source_ip": source_ip,
    }
    if occurred_at:
        row["occurred_at"] = occurred_at
    result = client.table("user_behavior_events").insert(row).execute()
    event = result.data[0]

    _evaluate_rules(client, event, asset_id=asset_id, hostname=hostname)
    return event


def _evaluate_rules(client, event, asset_id=None, hostname=None):
    username = event["username"]
    event_type = event["event_type"]

    if event_type == "failed_login":
        _check_failed_login_burst(client, username, asset_id=asset_id, hostname=hostname)

    if event_type == "login":
        _check_new_source_ip(client, username, event.get("source_ip"))
        _check_off_hours(username, event)


def _check_failed_login_burst(client, username, asset_id=None, hostname=None):
    window_start = (datetime.now(timezone.utc) - timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)).isoformat()
    result = (
        client.table("user_behavior_events")
        .select("id")
        .eq("username", username)
        .eq("event_type", "failed_login")
        .gte("occurred_at", window_start)
        .execute()
    )
    count = len(result.data)
    if count >= FAILED_LOGIN_THRESHOLD:
        severity = "critical" if count >= FAILED_LOGIN_CRITICAL_THRESHOLD else "high"
        where = f" on {hostname}" if hostname else ""
        alert_service.create_alert(
            alert_type="ueba_anomaly",
            title=f"Repeated failed logins for {username}",
            description=(
                f"Possible brute-force{where}: {count} failed logins for '{username}' "
                f"in the last {FAILED_LOGIN_WINDOW_MINUTES} minutes"
            ),
            severity=severity,
            asset_id=asset_id,
        )


def _check_new_source_ip(client, username, source_ip):
    # Local/loopback interactive logons are not a "new location" signal
    if not source_ip or source_ip.strip() in _LOCAL_SOURCE_IPS:
        return
    result = (
        client.table("user_behavior_events")
        .select("id")
        .eq("username", username)
        .eq("source_ip", source_ip)
        .eq("event_type", "login")
        .execute()
    )
    if len(result.data) <= 1:
        alert_service.create_alert(
            alert_type="ueba_anomaly",
            title=f"Login from new source IP for {username}",
            description=f"First observed login from {source_ip}",
            severity="medium",
        )


def _check_off_hours(username, event):
    occurred_at = event.get("occurred_at")
    if not occurred_at:
        return
    hour = datetime.fromisoformat(occurred_at.replace("Z", "+00:00")).hour
    if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
        alert_service.create_alert(
            alert_type="ueba_anomaly",
            title=f"Off-hours login for {username}",
            description=f"Login at {hour}:00 UTC, outside normal hours",
            severity="low",
        )


def list_events(username=None, event_type=None, limit=100):
    client = get_client()
    query = client.table("user_behavior_events").select("*").order("occurred_at", desc=True).limit(limit)
    if username:
        query = query.eq("username", username)
    if event_type:
        query = query.eq("event_type", event_type)
    return query.execute().data
