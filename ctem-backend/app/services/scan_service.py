import uuid
from datetime import datetime
from app.db.supabase_client import get_client
from app.services import target_validation


def find_existing_scan(target):
    client = get_client()
    result = client.table("scans").select("*").eq("target", target).order("created_at", desc=True).limit(1).execute()
    if result.data:
        return result.data[0]
    return None


def _clean_tenant_id(tenant_id):
    if not tenant_id:
        return None
    try:
        return str(uuid.UUID(str(tenant_id)))
    except (ValueError, AttributeError):
        return None


def create_scan(target, target_type, labels, tenant_id=None):
    client = get_client()
    scan_id = str(uuid.uuid4())
    row = {
        "scan_id": scan_id,
        "target": target,
        "target_type": target_type,
        "status": "queued",
        "labels": labels or {},
        "tenant_id": _clean_tenant_id(tenant_id),
        "created_at": datetime.utcnow().isoformat(),
    }
    client.table("scans").insert(row).execute()
    return row


def get_scan(scan_id):
    client = get_client()
    result = client.table("scans").select("*").eq("scan_id", scan_id).limit(1).execute()
    if result.data:
        return result.data[0]
    return None


def get_scan_history(target=None, tenant_id=None, limit=20):
    client = get_client()
    query = client.table("scans").select("*").order("created_at", desc=True).limit(limit)
    if target:
        query = query.eq("target", target)
    clean_tenant = _clean_tenant_id(tenant_id)
    if clean_tenant:
        query = query.eq("tenant_id", clean_tenant)
    result = query.execute()
    return result.data


def get_scan_assets(scan_id):
    client = get_client()
    join_result = client.table("scan_assets").select("asset_id").eq("scan_id", scan_id).execute()
    asset_ids = [row["asset_id"] for row in join_result.data]
    if not asset_ids:
        return []
    assets_result = client.table("assets").select("*").in_("id", asset_ids).execute()
    assets = assets_result.data or []

    # Fetch open ports and risk scores for these assets
    ports_res = client.table("open_ports").select("asset_id").in_("asset_id", asset_ids).execute()
    scores_res = client.table("risk_scores").select("asset_id, composite_score, priority_tier").in_("asset_id", asset_ids).execute()

    ports_count = {}
    for p in (ports_res.data or []):
        ports_count[p["asset_id"]] = ports_count.get(p["asset_id"], 0) + 1

    tier_order = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}
    highest_risk = {}
    for s in (scores_res.data or []):
        aid = s["asset_id"]
        tier = s.get("priority_tier") or "P4"
        score = float(s.get("composite_score") or 0.0)
        if aid not in highest_risk:
            highest_risk[aid] = {"tier": tier, "score": score}
        else:
            if tier_order.get(tier, 1) > tier_order.get(highest_risk[aid]["tier"], 1):
                highest_risk[aid]["tier"] = tier
            if score > highest_risk[aid]["score"]:
                highest_risk[aid]["score"] = score

    for a in assets:
        aid = a["id"]
        a["open_ports_count"] = ports_count.get(aid, 0)
        a["highest_tier"] = highest_risk.get(aid, {}).get("tier")
        a["max_score"] = highest_risk.get(aid, {}).get("score")

    return assets


def update_scan_status(scan_id, status, error_message=None):
    client = get_client()
    update = {"status": status}
    if status == "running" and error_message is None:
        update["started_at"] = datetime.utcnow().isoformat()
    if status in ("complete", "failed"):
        update["finished_at"] = datetime.utcnow().isoformat()
    if error_message:
        update["error_message"] = error_message
    client.table("scans").update(update).eq("scan_id", scan_id).execute()


def reset_scan_for_rerun(scan_id):
    client = get_client()
    update = {
        "status": "queued",
        "error_message": None,
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
    }
    client.table("scans").update(update).eq("scan_id", scan_id).execute()


def cancel_scan(scan_id):
    client = get_client()
    return client.table("scans").update({
        "status": "failed",
        "error_message": "Cancelled by user",
        "finished_at": datetime.utcnow().isoformat()
    }).eq("scan_id", scan_id).execute()


def delete_scan(scan_id):
    client = get_client()
    return client.table("scans").delete().eq("scan_id", scan_id).execute()


def link_asset_to_scan(scan_id, asset_id):
    client = get_client()
    client.table("scan_assets").upsert({"scan_id": scan_id, "asset_id": asset_id}).execute()


async def run_scan_pipeline(scan_id, target, target_type):
    import logging
    logger = logging.getLogger("ctem.pipeline")
    from app.services import recon_runner, ingestion_runner, scoring_runner

    try:
        logger.info(f"[PIPELINE] >>> Starting pipeline for scan_id={scan_id}, target={target}")
        update_scan_status(scan_id, "running")
        recon_output = await recon_runner.run_recon(target, target_type)

        hosts_count = len(recon_output.get("hosts", []))
        logger.info(f"[PIPELINE] Recon finished. Ingesting {hosts_count} host(s)...")
        update_scan_status(scan_id, "ingesting")
        asset_ids = await ingestion_runner.ingest_recon_output(scan_id, recon_output)
        for asset_id in asset_ids:
            link_asset_to_scan(scan_id, asset_id)

        logger.info(f"[PIPELINE] Ingestion finished. Scoring {len(asset_ids)} asset(s)...")
        update_scan_status(scan_id, "scoring")
        await scoring_runner.score_assets(asset_ids)

        logger.info(f"[PIPELINE] >>> Scan {scan_id} COMPLETED successfully!")
        update_scan_status(scan_id, "complete")
    except Exception as exc:
        logger.error(f"[PIPELINE] Scan {scan_id} FAILED: {exc}", exc_info=True)
        update_scan_status(scan_id, "failed", error_message=str(exc))
