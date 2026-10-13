from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from app.db.supabase_client import get_client
from app.services import blast_radius_service

router = APIRouter(prefix="/risk", tags=["risk"])


class BlastRadiusSimulationRequest(BaseModel):
    isolate_subnet: bool = False
    sever_dependencies: bool = False
    isolate_zone: bool = False
    mode: Optional[str] = "combined"


class AssetDependencyCreateRequest(BaseModel):
    asset_id: str
    depends_on_asset_id: str


@router.get("/scores")
async def list_risk_scores(priority_tier: str = None, min_score: float = None):
    client = get_client()
    query = client.table("risk_scores").select("*")
    if priority_tier:
        query = query.eq("priority_tier", priority_tier)
    if min_score is not None:
        query = query.gte("composite_score", min_score)
    result = query.execute()
    return {"risk_scores": result.data}


@router.get("/scores/{asset_id}")
async def get_asset_risk(asset_id: str):
    client = get_client()
    result = client.table("risk_scores").select("*").eq("asset_id", asset_id).execute()
    return {"asset_id": asset_id, "findings": result.data or []}


@router.get("/scores/{asset_id}/explain")
async def explain_asset_risk(asset_id: str):
    client = get_client()
    findings_result = client.table("risk_scores").select("*").eq("asset_id", asset_id).execute()
    if not findings_result.data:
        return {"asset_id": asset_id, "explanations": []}

    ports_result = client.table("open_ports").select("*").eq("asset_id", asset_id).execute()
    ports_by_product_version = {}
    for port in ports_result.data:
        key = (port.get("product"), port.get("version"))
        ports_by_product_version[key] = port

    explanations = []
    for finding in findings_result.data:
        key = (finding.get("matched_product"), finding.get("matched_version"))
        port_info = ports_by_product_version.get(key, {})
        explanations.append({
            "cve_id": finding.get("cve_id"),
            "matched_product": finding.get("matched_product"),
            "matched_version": finding.get("matched_version"),
            "port": port_info.get("port"),
            "protocol": port_info.get("protocol"),
            "composite_score": finding.get("composite_score"),
            "priority_tier": finding.get("priority_tier"),
            "criticality_mismatch": finding.get("criticality_mismatch"),
            "reason": f"{port_info.get('product', 'service')} {port_info.get('version', '')} on port {port_info.get('port', '?')} is affected by {finding.get('cve_id')}",
        })

    return {"asset_id": asset_id, "explanations": explanations}


@router.post("/rescore")
async def rescore_all_assets():
    from app.services import scoring_runner
    await scoring_runner.score_all_assets()
    return {"status": "ok", "message": "All assets rescored successfully"}


@router.get("/heatmap")
async def get_heatmap():
    client = get_client()
    scores_result = client.table("risk_scores").select("asset_id, composite_score, priority_tier, created_at, updated_at").execute()

    assets_result = client.table("assets").select("id, hostname, ip_address, zone, criticality").execute()
    all_assets = assets_result.data or []
    scored_asset_ids = {s["asset_id"] for s in (scores_result.data or [])}

    unscored_asset_ids = [a["id"] for a in all_assets if a["id"] not in scored_asset_ids]
    if unscored_asset_ids:
        from app.services import scoring_runner
        try:
            await scoring_runner.score_assets(unscored_asset_ids)
            scores_result = client.table("risk_scores").select("asset_id, composite_score, priority_tier, created_at, updated_at").execute()
        except Exception:
            pass

    assets_by_id = {asset["id"]: asset for asset in all_assets}

    tier_order = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}

    # Aggregate by asset_id to show unique assets with their highest risk
    aggregated = {}
    for score in (scores_result.data or []):
        asset_id = score["asset_id"]
        tier = score.get("priority_tier") or "P4"
        comp_score = float(score.get("composite_score") or 0.0)
        ts = score.get("updated_at") or score.get("created_at")

        if asset_id not in aggregated:
            aggregated[asset_id] = {
                "max_score": comp_score,
                "highest_tier": tier,
                "count": 1,
                "last_assessed": ts,
            }
        else:
            if comp_score > aggregated[asset_id]["max_score"]:
                aggregated[asset_id]["max_score"] = comp_score
            if tier_order.get(tier, 1) > tier_order.get(aggregated[asset_id]["highest_tier"], 1):
                aggregated[asset_id]["highest_tier"] = tier
            aggregated[asset_id]["count"] += 1
            if ts and (not aggregated[asset_id].get("last_assessed") or ts > aggregated[asset_id]["last_assessed"]):
                aggregated[asset_id]["last_assessed"] = ts

    heatmap = []
    for asset_id, data in aggregated.items():
        asset = assets_by_id.get(asset_id, {})
        heatmap.append({
            "asset_id": asset_id,
            "hostname": asset.get("hostname") or asset.get("ip_address") or asset_id,
            "zone": asset.get("zone"),
            "composite_score": round(data["max_score"], 2),
            "priority_tier": data["highest_tier"],
            "findings_count": data["count"],
            "last_assessed": data.get("last_assessed"),
        })

    # Sort heatmap by composite_score desc
    heatmap.sort(key=lambda x: x["composite_score"], reverse=True)

    return {"heatmap": heatmap}


# ==============================================================================
# BLAST RADIUS & LATERAL MOVEMENT ENDPOINTS
# ==============================================================================

@router.get("/blast-radius")
async def get_blast_radius_overview(mode: Optional[str] = "combined"):
    """
    Returns an organization-wide summary of blast radius across all assets,
    ranking the highest pivot risks and collateral damage candidates.
    """
    client = get_client()
    overview = blast_radius_service.get_all_assets_blast_radius(client, mode=mode)
    return overview


@router.get("/blast-radius/{asset_id}")
async def get_asset_blast_radius(asset_id: str, mode: Optional[str] = "combined", depth: int = 2):
    """
    Returns full blast radius analysis for a specific asset:
    direct 1st-hop reachable assets, transitive 2nd-hop cascade assets,
    attack paths, criticality breakdown, and containment recommendations.
    """
    client = get_client()
    result = blast_radius_service.get_asset_blast_radius(client, asset_id, mode=mode, max_depth=depth)
    if not result:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


@router.post("/blast-radius/{asset_id}/simulate")
async def simulate_blast_radius_containment(asset_id: str, request: BlastRadiusSimulationRequest):
    """
    Simulates containment controls (subnet isolation, severed dependencies, zone quarantine)
    and returns delta in blast radius multiplier and mitigated collateral assets.
    """
    client = get_client()
    try:
        simulation = blast_radius_service.simulate_containment(
            client=client,
            asset_id=asset_id,
            isolate_subnet=request.isolate_subnet,
            sever_dependencies=request.sever_dependencies,
            isolate_zone=request.isolate_zone,
            mode=request.mode,
        )
        return simulation
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ==============================================================================
# ASSET DEPENDENCY ENDPOINTS
# ==============================================================================

@router.get("/dependencies")
async def list_dependencies(asset_id: Optional[str] = None):
    """
    Lists asset dependency links, optionally filtered by asset_id (as source or target).
    """
    client = get_client()
    deps = blast_radius_service.list_asset_dependencies(client, asset_id=asset_id)
    return {"dependencies": deps}


@router.post("/dependencies")
async def create_dependency(request: AssetDependencyCreateRequest):
    """
    Declares a directional service dependency: asset_id -> depends_on_asset_id.
    Triggers risk rescore for the affected nodes.
    """
    client = get_client()
    try:
        created = blast_radius_service.add_asset_dependency(
            client,
            asset_id=request.asset_id,
            depends_on_asset_id=request.depends_on_asset_id,
        )
        # Rescore affected assets so risk_scores blast_radius is updated
        from app.services import scoring_runner
        try:
            await scoring_runner.score_assets([request.asset_id, request.depends_on_asset_id])
        except Exception:
            pass
        return {"status": "created", "dependency": created}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/dependencies/{dependency_id}")
async def delete_dependency(dependency_id: str):
    """
    Deletes an asset dependency link.
    """
    client = get_client()
    blast_radius_service.delete_asset_dependency(client, dependency_id)
    return {"status": "deleted", "dependency_id": dependency_id}
