import ipaddress
import uuid
from typing import Optional, List, Dict, Any
from app import config
from app.services import risk_engine


def count_related_assets(client, asset: Dict[str, Any], mode: Optional[str] = None) -> int:
    """
    Count related reachable assets for an asset based on reachability mode.
    Maintains compatibility with risk scoring runner.
    """
    selected_mode = mode or config.BLAST_RADIUS_REACHABILITY_MODE
    if selected_mode == "same_subnet":
        return _count_same_subnet(client, asset)
    if selected_mode == "same_zone":
        return _count_same_zone(client, asset)
    if selected_mode == "dependency_edges":
        return _count_dependencies(client, asset)
    if selected_mode == "combined":
        return _count_combined(client, asset)
    return _count_same_subnet(client, asset)


def _count_same_subnet(client, asset: Dict[str, Any]) -> int:
    ip_address = asset.get("ip_address")
    if not ip_address:
        return _count_same_zone(client, asset)
    try:
        network = ipaddress.ip_network(f"{ip_address}/24", strict=False)
    except ValueError:
        return _count_same_zone(client, asset)

    result = client.table("assets").select("id, ip_address").execute()
    count = 0
    for row in result.data or []:
        other_ip = row.get("ip_address")
        if not other_ip or row["id"] == asset["id"]:
            continue
        try:
            if ipaddress.ip_address(other_ip) in network:
                count += 1
        except ValueError:
            continue
    return count


def _count_same_zone(client, asset: Dict[str, Any]) -> int:
    zone = asset.get("zone")
    if not zone:
        return 0
    result = client.table("assets").select("id").eq("zone", zone).execute()
    return max(len(result.data or []) - 1, 0)


def _count_dependencies(client, asset: Dict[str, Any]) -> int:
    # Check both outgoing and incoming dependency edges
    out_res = client.table("asset_dependencies").select("id").eq("asset_id", asset["id"]).execute()
    in_res = client.table("asset_dependencies").select("id").eq("depends_on_asset_id", asset["id"]).execute()
    connected_ids = set()
    for row in (out_res.data or []):
        connected_ids.add(row["id"])
    for row in (in_res.data or []):
        connected_ids.add(row["id"])
    return len(connected_ids)


def _count_combined(client, asset: Dict[str, Any]) -> int:
    # Union of subnet, zone, and dependency reachable assets
    all_assets_res = client.table("assets").select("id, ip_address, zone").execute()
    all_assets = all_assets_res.data or []
    asset_id = asset.get("id")

    reachable_ids = set()

    # Subnet
    target_ip = asset.get("ip_address")
    subnet_net = None
    if target_ip:
        try:
            subnet_net = ipaddress.ip_network(f"{target_ip}/24", strict=False)
        except ValueError:
            pass

    target_zone = asset.get("zone")

    for other in all_assets:
        other_id = other.get("id")
        if other_id == asset_id:
            continue

        # Subnet match
        if subnet_net and other.get("ip_address"):
            try:
                if ipaddress.ip_address(other["ip_address"]) in subnet_net:
                    reachable_ids.add(other_id)
                    continue
            except ValueError:
                pass

        # Zone match
        if target_zone and other.get("zone") == target_zone:
            reachable_ids.add(other_id)

    # Dependencies
    deps_res = client.table("asset_dependencies").select("asset_id, depends_on_asset_id").execute()
    for dep in (deps_res.data or []):
        src = dep.get("asset_id")
        tgt = dep.get("depends_on_asset_id")
        if src == asset_id and tgt and tgt != asset_id:
            reachable_ids.add(tgt)
        elif tgt == asset_id and src and src != asset_id:
            reachable_ids.add(src)

    return len(reachable_ids)


# ==============================================================================
# DEPENDENCY MANAGEMENT
# ==============================================================================

def list_asset_dependencies(client, asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = client.table("asset_dependencies").select("*")
    if asset_id:
        # Outgoing or incoming
        query = query.or_(f"asset_id.eq.{asset_id},depends_on_asset_id.eq.{asset_id}")
    deps_res = query.order("created_at", desc=True).execute()
    deps = deps_res.data or []

    if not deps:
        return []

    # Enrich with asset details
    all_assets_res = client.table("assets").select("id, hostname, ip_address, zone, criticality, asset_type").execute()
    assets_by_id = {a["id"]: a for a in (all_assets_res.data or [])}

    enriched = []
    for dep in deps:
        source = assets_by_id.get(dep["asset_id"], {})
        target = assets_by_id.get(dep["depends_on_asset_id"], {})
        enriched.append({
            "id": dep["id"],
            "asset_id": dep["asset_id"],
            "depends_on_asset_id": dep["depends_on_asset_id"],
            "created_at": dep.get("created_at"),
            "source_asset": {
                "id": dep["asset_id"],
                "hostname": source.get("hostname"),
                "ip_address": source.get("ip_address"),
                "zone": source.get("zone"),
                "criticality": source.get("criticality", "low"),
                "asset_type": source.get("asset_type"),
            },
            "target_asset": {
                "id": dep["depends_on_asset_id"],
                "hostname": target.get("hostname"),
                "ip_address": target.get("ip_address"),
                "zone": target.get("zone"),
                "criticality": target.get("criticality", "low"),
                "asset_type": target.get("asset_type"),
            },
        })
    return enriched


def add_asset_dependency(client, asset_id: str, depends_on_asset_id: str) -> Dict[str, Any]:
    if asset_id == depends_on_asset_id:
        raise ValueError("An asset cannot declare a dependency on itself.")

    # Validate that both assets exist
    src_res = client.table("assets").select("id, hostname, ip_address").eq("id", asset_id).limit(1).execute()
    if not src_res.data:
        raise ValueError(f"Source asset {asset_id} not found.")

    tgt_res = client.table("assets").select("id, hostname, ip_address").eq("id", depends_on_asset_id).limit(1).execute()
    if not tgt_res.data:
        raise ValueError(f"Target dependency asset {depends_on_asset_id} not found.")

    # Check for existing duplicate link
    dup_res = (
        client.table("asset_dependencies")
        .select("id")
        .eq("asset_id", asset_id)
        .eq("depends_on_asset_id", depends_on_asset_id)
        .limit(1)
        .execute()
    )
    if dup_res.data:
        return dup_res.data[0]

    row = {
        "id": str(uuid.uuid4()),
        "asset_id": asset_id,
        "depends_on_asset_id": depends_on_asset_id,
    }
    result = client.table("asset_dependencies").insert(row).execute()
    return result.data[0] if result.data else row


def delete_asset_dependency(client, dependency_id: str) -> bool:
    client.table("asset_dependencies").delete().eq("id", dependency_id).execute()
    return True


# ==============================================================================
# DETAILED ASSET BLAST RADIUS CALCULATION
# ==============================================================================

def get_asset_blast_radius(
    client,
    asset_id: str,
    mode: Optional[str] = "combined",
    max_depth: int = 2,
    isolate_subnet: bool = False,
    sever_dependencies: bool = False,
    isolate_zone: bool = False,
    prefetched: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Computes a comprehensive blast radius analysis for an asset.
    Returns direct and transitive reachable assets, attack paths, exposed ports,
    criticality breakdown, and remediation recommendations.
    """
    if prefetched:
        assets_by_id = prefetched["assets_by_id"]
        target_asset = assets_by_id.get(asset_id)
        if not target_asset:
            return None
        ports_by_asset = prefetched["ports_by_asset"]
        max_score_by_asset = prefetched["max_score_by_asset"]
        tier_by_asset = prefetched["tier_by_asset"]
        all_dependencies = prefetched["all_dependencies"]
    else:
        # 1. Fetch target asset
        asset_res = client.table("assets").select("*").eq("id", asset_id).limit(1).execute()
        if not asset_res.data:
            return None
        target_asset = asset_res.data[0]

        # 2. Fetch all assets
        all_assets_res = client.table("assets").select("*").execute()
        all_assets = all_assets_res.data or []
        assets_by_id = {a["id"]: a for a in all_assets}

        # 3. Fetch open ports for all assets
        ports_res = client.table("open_ports").select("*").execute()
        ports_by_asset = {}
        for p in (ports_res.data or []):
            aid = p.get("asset_id")
            if aid not in ports_by_asset:
                ports_by_asset[aid] = []
            ports_by_asset[aid].append(p)

        # 4. Fetch risk scores to get composite risk / priority tier
        scores_res = client.table("risk_scores").select("asset_id, composite_score, priority_tier").execute()
        max_score_by_asset = {}
        tier_by_asset = {}
        tier_rank = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}
        for sc in (scores_res.data or []):
            aid = sc.get("asset_id")
            s = float(sc.get("composite_score") or 0.0)
            t = sc.get("priority_tier") or "P4"
            if aid not in max_score_by_asset or s > max_score_by_asset[aid]:
                max_score_by_asset[aid] = s
            if aid not in tier_by_asset or tier_rank.get(t, 1) > tier_rank.get(tier_by_asset[aid], 1):
                tier_by_asset[aid] = t

        # 5. Fetch dependencies
        deps_res = client.table("asset_dependencies").select("*").execute()
        all_dependencies = deps_res.data or []

    # Build adjacency maps for dependencies
    # outgoing: asset_id -> set(depends_on)
    # incoming: depends_on -> set(asset_id)
    dep_outgoing = {}
    dep_incoming = {}
    for dep in all_dependencies:
        src = dep.get("asset_id")
        tgt = dep.get("depends_on_asset_id")
        if src and tgt:
            dep_outgoing.setdefault(src, set()).add(tgt)
            dep_incoming.setdefault(tgt, set()).add(src)

    # Determine reachability vector parameters
    effective_mode = mode or "combined"

    # Setup Subnet Network
    target_ip = target_asset.get("ip_address")
    target_subnet = None
    if target_ip and not isolate_subnet:
        try:
            target_subnet = ipaddress.ip_network(f"{target_ip}/24", strict=False)
        except ValueError:
            pass

    target_zone = target_asset.get("zone") if not isolate_zone else None

    # Track 1st-Hop Reachable Assets
    # format: asset_id -> set of vector reasons ("subnet", "zone", "dependency_upstream", "dependency_downstream")
    first_hop = {}
    attack_paths = []

    for other_id, other in assets_by_id.items():
        if other_id == asset_id:
            continue

        vectors = set()

        # A. Check Subnet Vector
        if (effective_mode in ("same_subnet", "combined")) and not isolate_subnet and target_subnet:
            other_ip = other.get("ip_address")
            if other_ip:
                try:
                    if ipaddress.ip_address(other_ip) in target_subnet:
                        vectors.add("same_subnet")
                except ValueError:
                    pass

        # B. Check Zone Vector
        if (effective_mode in ("same_zone", "combined")) and not isolate_zone:
            if target_zone and other.get("zone") == target_zone:
                vectors.add("same_zone")

        # C. Check Dependency Vector
        if (effective_mode in ("dependency_edges", "combined")) and not sever_dependencies:
            if other_id in dep_outgoing.get(asset_id, set()):
                vectors.add("dependency_downstream")
            if other_id in dep_incoming.get(asset_id, set()):
                vectors.add("dependency_upstream")

        if vectors:
            first_hop[other_id] = vectors
            for v in vectors:
                attack_paths.append({
                    "from_asset_id": asset_id,
                    "to_asset_id": other_id,
                    "hop": 1,
                    "vector": v,
                    "description": _format_vector_description(target_asset, other, v, target_subnet),
                })

    # Track 2nd-Hop Cascade Reachable Assets
    second_hop = {}
    if max_depth >= 2:
        for f_id in list(first_hop.keys()):
            f_asset = assets_by_id.get(f_id, {})
            # Look for dependency expansions or subnet expansions from 1st hop assets
            candidate_ids = set()
            if not sever_dependencies and effective_mode in ("dependency_edges", "combined"):
                candidate_ids.update(dep_outgoing.get(f_id, set()))
                candidate_ids.update(dep_incoming.get(f_id, set()))

            for cand_id in candidate_ids:
                if cand_id != asset_id and cand_id not in first_hop and cand_id in assets_by_id:
                    cand_vectors = second_hop.setdefault(cand_id, set())
                    cand_vectors.add("cascade_dependency")
                    attack_paths.append({
                        "from_asset_id": f_id,
                        "to_asset_id": cand_id,
                        "hop": 2,
                        "vector": "cascade_dependency",
                        "description": f"Transitive pivot via {f_asset.get('hostname') or f_asset.get('ip_address') or f_id} through service dependency link",
                    })

    # Build detailed list of reachable assets
    reachable_assets = []
    all_affected_ids = set(first_hop.keys()) | set(second_hop.keys())

    criticality_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for aff_id in all_affected_ids:
        aff = assets_by_id.get(aff_id, {})
        crit = aff.get("criticality") or "low"
        criticality_counts[crit] = criticality_counts.get(crit, 0) + 1

        is_first = aff_id in first_hop
        hop_num = 1 if is_first else 2
        vectors_list = sorted(list(first_hop.get(aff_id, second_hop.get(aff_id, set()))))

        aff_ports = ports_by_asset.get(aff_id, [])

        reachable_assets.append({
            "id": aff_id,
            "hostname": aff.get("hostname"),
            "ip_address": aff.get("ip_address"),
            "zone": aff.get("zone"),
            "criticality": crit,
            "asset_type": aff.get("asset_type"),
            "asset_status": aff.get("asset_status"),
            "hop": hop_num,
            "vectors": vectors_list,
            "composite_score": max_score_by_asset.get(aff_id, 0.0),
            "priority_tier": tier_by_asset.get(aff_id, "P4"),
            "open_ports_count": len(aff_ports),
            "open_ports": aff_ports[:5],  # top 5 ports for quick inspection
        })

    # Sort reachable assets by criticality (critical first), then composite score desc
    crit_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    reachable_assets.sort(
        key=lambda x: (crit_order.get(x["criticality"], 1), x["composite_score"]),
        reverse=True,
    )

    # Compute Blast Radius Multiplier (capped between 1.0 and 2.0)
    direct_count = len(first_hop)
    blast_radius_multiplier = risk_engine.compute_blast_radius(direct_count)

    # Compute Exposure Severity
    if criticality_counts["critical"] > 0 and blast_radius_multiplier >= 1.7:
        exposure_level = "Catastrophic"
    elif criticality_counts["critical"] > 0 or criticality_counts["high"] >= 2 or direct_count >= 5:
        exposure_level = "High"
    elif direct_count >= 1 or criticality_counts["medium"] >= 2:
        exposure_level = "Moderate"
    else:
        exposure_level = "Contained"

    # Generate Containment Recommendations
    recommendations = _generate_recommendations(
        target_asset,
        first_hop,
        criticality_counts,
        isolate_subnet,
        sever_dependencies,
        isolate_zone,
    )

    # Format graph nodes for frontend visualizer
    graph_nodes = [
        {
            "id": asset_id,
            "label": target_asset.get("hostname") or target_asset.get("ip_address") or "Target",
            "ip_address": target_asset.get("ip_address"),
            "zone": target_asset.get("zone"),
            "criticality": target_asset.get("criticality", "low"),
            "asset_type": target_asset.get("asset_type"),
            "is_target": True,
            "hop": 0,
            "composite_score": max_score_by_asset.get(asset_id, 0.0),
            "priority_tier": tier_by_asset.get(asset_id, "P4"),
            "ports_count": len(ports_by_asset.get(asset_id, [])),
        }
    ]
    for r in reachable_assets:
        graph_nodes.append({
            "id": r["id"],
            "label": r["hostname"] or r["ip_address"] or r["id"][:8],
            "ip_address": r["ip_address"],
            "zone": r["zone"],
            "criticality": r["criticality"],
            "asset_type": r["asset_type"],
            "is_target": False,
            "hop": r["hop"],
            "vectors": r["vectors"],
            "composite_score": r["composite_score"],
            "priority_tier": r["priority_tier"],
            "ports_count": r["open_ports_count"],
        })

    return {
        "asset": {
            "id": target_asset["id"],
            "hostname": target_asset.get("hostname"),
            "ip_address": target_asset.get("ip_address"),
            "zone": target_asset.get("zone"),
            "criticality": target_asset.get("criticality", "low"),
            "asset_type": target_asset.get("asset_type"),
            "asset_status": target_asset.get("asset_status"),
            "composite_score": max_score_by_asset.get(asset_id, 0.0),
            "priority_tier": tier_by_asset.get(asset_id, "P4"),
            "open_ports_count": len(ports_by_asset.get(asset_id, [])),
            "open_ports": ports_by_asset.get(asset_id, []),
        },
        "reachability_mode": effective_mode,
        "blast_radius_multiplier": blast_radius_multiplier,
        "direct_reachable_count": direct_count,
        "cascade_reachable_count": len(second_hop),
        "total_affected_count": len(all_affected_ids),
        "exposure_level": exposure_level,
        "criticality_breakdown": criticality_counts,
        "reachable_assets": reachable_assets,
        "attack_paths": attack_paths,
        "graph": {
            "nodes": graph_nodes,
            "edges": attack_paths,
        },
        "recommendations": recommendations,
        "simulation_state": {
            "isolate_subnet": isolate_subnet,
            "sever_dependencies": sever_dependencies,
            "isolate_zone": isolate_zone,
        },
    }


def _format_vector_description(src, dst, vector, subnet):
    src_name = src.get("hostname") or src.get("ip_address") or "Source"
    dst_name = dst.get("hostname") or dst.get("ip_address") or "Target"
    if vector == "same_subnet":
        return f"Direct L2/L3 reachability in shared subnet ({subnet or '/24'})"
    if vector == "same_zone":
        return f"Co-located within identical network security zone ({src.get('zone') or 'unassigned'})"
    if vector == "dependency_downstream":
        return f"{src_name} has declared service dependency on {dst_name}"
    if vector == "dependency_upstream":
        return f"{dst_name} relies on {src_name} for upstream service operations"
    return f"Reachable via {vector}"


def _generate_recommendations(
    target,
    first_hop,
    criticality_counts,
    isolate_subnet,
    sever_dependencies,
    isolate_zone,
) -> List[str]:
    recs = []
    target_name = target.get("hostname") or target.get("ip_address") or "Asset"

    if criticality_counts["critical"] > 0:
        recs.append(
            f"URGENT: {criticality_counts['critical']} CRITICAL asset(s) are directly reachable from {target_name}. "
            f"Apply immediate egress firewall ACLs to isolate traffic towards crown-jewel assets."
        )

    if target.get("ip_address") and not isolate_subnet:
        recs.append(
            f"Implement micro-segmentation or private VLAN (PVLAN) around {target.get('ip_address')} "
            f"to block lateral ARP/L2 scanning across the local subnet."
        )

    if target.get("zone") == "external":
        recs.append(
            f"{target_name} is in the EXTERNAL zone. Restrict ingress and ensure reverse proxy/WAF inspection "
            f"is enforced to prevent external pivot into the internal network."
        )

    if len(first_hop) > 5:
        recs.append(
            f"High blast radius density ({len(first_hop)} direct neighbors). "
            f"Deploy Host-based Intrusion Detection (HIDS) or zero-trust network access (ZTNA) agents."
        )

    if not recs:
        recs.append(f"{target_name} has limited lateral exposure. Maintain standard patch hygiene and logging.")

    return recs


# ==============================================================================
# ORG-WIDE BLAST RADIUS OVERVIEW
# ==============================================================================

def get_all_assets_blast_radius(client, mode: Optional[str] = "combined") -> Dict[str, Any]:
    """
    Computes an organization-wide blast radius summary ranking all assets by lateral exposure.
    """
    all_assets_res = client.table("assets").select("*").execute()
    assets = all_assets_res.data or []
    assets_by_id = {a["id"]: a for a in assets}

    ports_res = client.table("open_ports").select("*").execute()
    ports_by_asset = {}
    for p in (ports_res.data or []):
        aid = p.get("asset_id")
        if aid not in ports_by_asset:
            ports_by_asset[aid] = []
        ports_by_asset[aid].append(p)

    scores_res = client.table("risk_scores").select("asset_id, composite_score, priority_tier").execute()
    max_score_by_asset = {}
    tier_by_asset = {}
    tier_rank = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}
    for sc in (scores_res.data or []):
        aid = sc.get("asset_id")
        s = float(sc.get("composite_score") or 0.0)
        t = sc.get("priority_tier") or "P4"
        if aid not in max_score_by_asset or s > max_score_by_asset[aid]:
            max_score_by_asset[aid] = s
        if aid not in tier_by_asset or tier_rank.get(t, 1) > tier_rank.get(tier_by_asset[aid], 1):
            tier_by_asset[aid] = t

    deps_res = client.table("asset_dependencies").select("*").execute()
    all_dependencies = deps_res.data or []
    total_deps = len(all_dependencies)

    prefetched = {
        "assets_by_id": assets_by_id,
        "ports_by_asset": ports_by_asset,
        "max_score_by_asset": max_score_by_asset,
        "tier_by_asset": tier_by_asset,
        "all_dependencies": all_dependencies,
    }

    ranked_assets = []
    total_multiplier = 0.0
    critical_at_risk_total = 0

    for a in assets:
        br = get_asset_blast_radius(client, a["id"], mode=mode, max_depth=1, prefetched=prefetched)
        if not br:
            continue

        mult = br["blast_radius_multiplier"]
        total_multiplier += mult
        crit_count = br["criticality_breakdown"]["critical"]
        if crit_count > 0:
            critical_at_risk_total += 1

        ranked_assets.append({
            "asset_id": a["id"],
            "hostname": a.get("hostname"),
            "ip_address": a.get("ip_address"),
            "zone": a.get("zone"),
            "criticality": a.get("criticality", "low"),
            "asset_type": a.get("asset_type"),
            "blast_radius_multiplier": mult,
            "direct_reachable_count": br["direct_reachable_count"],
            "total_affected_count": br["total_affected_count"],
            "exposure_level": br["exposure_level"],
            "critical_assets_at_risk": crit_count,
            "high_assets_at_risk": br["criticality_breakdown"]["high"],
        })

    # Sort ranked assets: highest multiplier desc, then critical_assets_at_risk desc
    ranked_assets.sort(
        key=lambda x: (x["blast_radius_multiplier"], x["critical_assets_at_risk"], x["total_affected_count"]),
        reverse=True,
    )

    avg_radius = round(total_multiplier / len(assets), 2) if assets else 1.0
    highest_radius = ranked_assets[0]["blast_radius_multiplier"] if ranked_assets else 1.0

    return {
        "reachability_mode": mode or "combined",
        "total_assets": len(assets),
        "total_dependencies": total_deps,
        "avg_blast_radius": avg_radius,
        "highest_blast_radius": highest_radius,
        "assets_with_critical_exposure": critical_at_risk_total,
        "ranked_assets": ranked_assets,
    }


# ==============================================================================
# CONTAINMENT SIMULATION ("WHAT-IF" SANDBOX)
# ==============================================================================

def simulate_containment(
    client,
    asset_id: str,
    isolate_subnet: bool = False,
    sever_dependencies: bool = False,
    isolate_zone: bool = False,
    mode: Optional[str] = "combined",
) -> Dict[str, Any]:
    """
    Simulates containment controls on an asset and calculates risk reduction metrics.
    """
    baseline = get_asset_blast_radius(
        client,
        asset_id,
        mode=mode,
        isolate_subnet=False,
        sever_dependencies=False,
        isolate_zone=False,
    )
    if not baseline:
        raise ValueError(f"Asset {asset_id} not found.")

    simulated = get_asset_blast_radius(
        client,
        asset_id,
        mode=mode,
        isolate_subnet=isolate_subnet,
        sever_dependencies=sever_dependencies,
        isolate_zone=isolate_zone,
    )

    baseline_total = baseline["total_affected_count"]
    simulated_total = simulated["total_affected_count"]
    mitigated_count = max(baseline_total - simulated_total, 0)

    # Reduction %
    if baseline_total > 0:
        reduction_pct = round((mitigated_count / baseline_total) * 100, 1)
    else:
        reduction_pct = 0.0

    # Multiplier delta
    multiplier_reduction = round(baseline["blast_radius_multiplier"] - simulated["blast_radius_multiplier"], 2)

    return {
        "asset_id": asset_id,
        "controls_applied": {
            "isolate_subnet": isolate_subnet,
            "sever_dependencies": sever_dependencies,
            "isolate_zone": isolate_zone,
        },
        "baseline": {
            "blast_radius_multiplier": baseline["blast_radius_multiplier"],
            "total_affected_count": baseline_total,
            "direct_reachable_count": baseline["direct_reachable_count"],
            "critical_assets_at_risk": baseline["criticality_breakdown"]["critical"],
            "exposure_level": baseline["exposure_level"],
        },
        "simulated": {
            "blast_radius_multiplier": simulated["blast_radius_multiplier"],
            "total_affected_count": simulated_total,
            "direct_reachable_count": simulated["direct_reachable_count"],
            "critical_assets_at_risk": simulated["criticality_breakdown"]["critical"],
            "exposure_level": simulated["exposure_level"],
        },
        "impact": {
            "mitigated_assets_count": mitigated_count,
            "risk_reduction_pct": reduction_pct,
            "multiplier_reduction": multiplier_reduction,
        },
        "simulated_blast_radius": simulated,
    }
