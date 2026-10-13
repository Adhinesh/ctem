from app.db.supabase_client import get_client


async def ingest_recon_output(scan_id, recon_output):
    client = get_client()
    asset_ids = []
    target = recon_output.get("target")
    scan_ports_snapshot = {}

    for host in recon_output.get("hosts", []):
        asset_id = _resolve_or_create_asset(client, host, recon_output.get("target_type"))
        current_ports = host.get("open_ports", [])

        prev_scan, is_first_scan = _find_previous_completed_scan(client, asset_id, scan_id, target=target)

        prev_ports = None
        if prev_scan:
            prev_labels = prev_scan.get("labels") or {}
            prev_ports_map = prev_labels.get("scan_ports") or {}
            prev_ports = prev_ports_map.get(str(asset_id))
            if prev_ports is None:
                # If earlier scan lacked labels.scan_ports, fallback to open_ports
                res = client.table("open_ports").select("*").eq("asset_id", asset_id).execute()
                prev_ports = res.data or []

        _record_open_ports(client, asset_id, current_ports, is_first_scan=is_first_scan, prev_ports=prev_ports)
        scan_ports_snapshot[str(asset_id)] = current_ports
        asset_ids.append(asset_id)

    # Persist the snapshot of detected ports in this scan's labels for future diffing
    if scan_id:
        try:
            curr_scan = client.table("scans").select("labels").eq("scan_id", scan_id).limit(1).execute()
            current_labels = (curr_scan.data[0].get("labels") if curr_scan.data else {}) or {}
            current_labels["scan_ports"] = scan_ports_snapshot
            client.table("scans").update({"labels": current_labels}).eq("scan_id", scan_id).execute()
        except Exception:
            pass

    return asset_ids


def _find_previous_completed_scan(client, asset_id, current_scan_id, target=None):
    """
    Finds the most recent completed scan for this asset or target prior to current_scan_id.
    Returns (prev_scan_row, is_first_scan).
    """
    prev_scan_ids = set()

    # 1. Check scan_assets join table
    try:
        joins = client.table("scan_assets").select("scan_id").eq("asset_id", asset_id).execute()
        for r in (joins.data or []):
            sid = r.get("scan_id")
            if sid and sid != current_scan_id:
                prev_scan_ids.add(sid)
    except Exception:
        pass

    # 2. Check scans for target if provided
    if target:
        try:
            t_res = client.table("scans").select("scan_id").eq("target", target).eq("status", "complete").execute()
            for r in (t_res.data or []):
                sid = r.get("scan_id")
                if sid and sid != current_scan_id:
                    prev_scan_ids.add(sid)
        except Exception:
            pass

    # 3. Check asset IP / hostname as targets
    try:
        asset_res = client.table("assets").select("ip_address, hostname").eq("id", asset_id).limit(1).execute()
        if asset_res.data:
            a = asset_res.data[0]
            targets_to_check = [val for val in (a.get("ip_address"), a.get("hostname")) if val and val != target]
            for t in targets_to_check:
                res = client.table("scans").select("scan_id").eq("target", t).eq("status", "complete").execute()
                for r in (res.data or []):
                    sid = r.get("scan_id")
                    if sid and sid != current_scan_id:
                        prev_scan_ids.add(sid)
    except Exception:
        pass

    if not prev_scan_ids:
        return None, True

    # Retrieve most recent completed scan
    try:
        scans_res = client.table("scans").select("*").in_("scan_id", list(prev_scan_ids)).eq("status", "complete").order("created_at", desc=True).limit(1).execute()
        if scans_res.data:
            return scans_res.data[0], False
    except Exception:
        pass

    return None, True


def _resolve_or_create_asset(client, host, target_type):
    hostname = host.get("hostname")
    ip_address = host.get("ip_address")
    cidr = host.get("cidr")

    existing = None
    if hostname:
        existing = client.table("assets").select("*").eq("hostname", hostname).limit(1).execute()
    elif ip_address:
        existing = client.table("assets").select("*").eq("ip_address", ip_address).limit(1).execute()

    if existing and existing.data:
        return existing.data[0]["id"]

    probe = host.get("http_probe", {})
    is_internet_facing = bool(probe.get("status_code"))

    new_asset = {
        "hostname": hostname,
        "ip_address": ip_address,
        "cidr": cidr,
        "asset_status": "discovered",
        "asset_confirmed": False,
        "zone": "external" if is_internet_facing else "internal",
        "asset_type": _infer_asset_type(target_type),
        "criticality": "low",
    }

    result = client.table("assets").insert(new_asset).execute()
    return result.data[0]["id"]


def _infer_asset_type(target_type):
    mapping = {
        "domain": "endpoint",
        "ip": "server",
        "cidr": "network_segment",
        "cloud_project": "cloud_resource",
    }
    return mapping.get(target_type, "endpoint")


def _record_open_ports(client, asset_id, open_ports, is_first_scan=False, prev_ports=None):
    from app.services import change_detection_service, alert_service

    curr_by_key = {
        (str(p.get("port")), str(p.get("protocol", "tcp")).lower()): p
        for p in open_ports
        if p.get("port") and not change_detection_service._is_ephemeral(p.get("port"))
    }

    if is_first_scan:
        # FIRST SCAN:
        # Only populate the "New" section (previous_value = None).
        # Previous section remains empty (-).
        # NEVER record any port_closed events!
        for key, port in curr_by_key.items():
            port_label = f"{port.get('port')}/{port.get('protocol', 'tcp').lower()}"
            change_detection_service._log_change(client, asset_id, "port_opened", None, port_label)

            client.table("open_ports").upsert({
                "asset_id": asset_id,
                "port": str(port.get("port")),
                "protocol": str(port.get("protocol", "tcp")).lower(),
                "service": port.get("service"),
                "product": port.get("product"),
                "version": port.get("version"),
            }, on_conflict="asset_id,port,protocol").execute()
        return

    # SUBSEQUENT SCAN (Comparing current scan vs previous scan):
    prev_by_key = {}
    if prev_ports:
        prev_by_key = {
            (str(p.get("port")), str(p.get("protocol", "tcp")).lower()): p
            for p in prev_ports
            if p.get("port") and not change_detection_service._is_ephemeral(p.get("port"))
        }

    # 1. Newly opened ports in this scan (not present in previous scan)
    for key, port in curr_by_key.items():
        port_label = f"{port.get('port')}/{port.get('protocol', 'tcp').lower()}"
        if key not in prev_by_key:
            change_detection_service._log_change(client, asset_id, "port_opened", None, port_label)
            alert_service.create_alert(
                alert_type="asset_change",
                title=f"New port opened on asset: {port_label}",
                description=f"Port {port_label} ({port.get('service') or 'unknown'}) newly detected via scan comparison",
                severity="medium",
                asset_id=asset_id,
            )
        else:
            # Present in both scans: check for service or version drift
            prev_item = prev_by_key[key]
            if prev_item.get("version") and port.get("version") and prev_item.get("version") != port.get("version"):
                change_detection_service._log_change(
                    client, asset_id, "version_changed",
                    prev_item.get("version"), port.get("version")
                )
                alert_service.create_alert(
                    alert_type="asset_change",
                    title="Service version changed",
                    description=f"Port {port.get('port')} changed from {prev_item.get('version')} to {port.get('version')}",
                    severity="low",
                    asset_id=asset_id,
                )
            elif prev_item.get("service") and port.get("service") and prev_item.get("service") != port.get("service"):
                change_detection_service._log_change(
                    client, asset_id, "service_changed",
                    prev_item.get("service"), port.get("service")
                )
                alert_service.create_alert(
                    alert_type="asset_change",
                    title="Service changed on existing port",
                    description=f"Port {port.get('port')} service changed from {prev_item.get('service')} to {port.get('service')}",
                    severity="medium",
                    asset_id=asset_id,
                )

        client.table("open_ports").upsert({
            "asset_id": asset_id,
            "port": str(port.get("port")),
            "protocol": str(port.get("protocol", "tcp")).lower(),
            "service": port.get("service"),
            "product": port.get("product"),
            "version": port.get("version"),
        }, on_conflict="asset_id,port,protocol").execute()

    # 2. Ports that were in previous scan, but are missing in current scan -> port_closed
    for key, prev_item in prev_by_key.items():
        if key not in curr_by_key:
            port_label = f"{prev_item.get('port')}/{prev_item.get('protocol', 'tcp').lower()}"
            change_detection_service._log_change(client, asset_id, "port_closed", port_label, None)
            try:
                client.table("open_ports").delete().eq("asset_id", asset_id).eq("port", str(prev_item.get("port"))).eq("protocol", str(prev_item.get("protocol", "tcp")).lower()).execute()
            except Exception:
                pass
            port_num = prev_item.get("port")
            if port_num:
                try:
                    client.table("risk_scores").delete().eq("asset_id", asset_id).eq("cve_id", f"CVE-PORT-{port_num}").execute()
                except Exception:
                    pass


def confirm_asset(asset_id):
    client = get_client()
    client.table("assets").update({"asset_status": "confirmed", "asset_confirmed": True}).eq("id", asset_id).execute()


def edit_asset(asset_id, fields):
    client = get_client()
    client.table("assets").update(fields).eq("id", asset_id).execute()


def delete_asset(asset_id):
    client = get_client()
    client.table("assets").delete().eq("id", asset_id).execute()
