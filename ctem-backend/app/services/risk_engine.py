from app import config


def compute_base_score(cvss_base):
    if cvss_base is None:
        return 0.0
    return cvss_base * 10


def compute_exploit_score(epss):
    return epss * 100


def compute_kev_multiplier(kev_listed):
    if kev_listed:
        return config.KEV_MULTIPLIER_LISTED
    return config.KEV_MULTIPLIER_UNLISTED


def compute_asset_weight(asset_criticality):
    key = asset_criticality.lower() if asset_criticality else "low"
    return config.ASSET_WEIGHT.get(key, config.ASSET_WEIGHT["low"])


def compute_exposure_multiplier(exposure_context):
    key = exposure_context.lower() if exposure_context else "restricted"
    return config.EXPOSURE_MULTIPLIER.get(key, config.EXPOSURE_MULTIPLIER["restricted"])


def compute_zone_bonus(zone):
    key = zone.lower() if zone else "external"
    return config.ZONE_WEIGHT_BONUS.get(key, config.ZONE_WEIGHT_BONUS["external"])


def compute_blast_radius(related_asset_count, mode=None):
    mode = mode or config.BLAST_RADIUS_REACHABILITY_MODE
    radius = config.BLAST_RADIUS_MIN + related_asset_count * config.BLAST_RADIUS_PER_RELATED_ASSET
    if radius > config.BLAST_RADIUS_MAX:
        return config.BLAST_RADIUS_MAX
    return radius


def compute_composite_score(cvss_base, epss, kev_listed, asset_criticality, exposure_context, zone, blast_radius):
    base_score = compute_base_score(cvss_base)
    exploit_score = compute_exploit_score(epss)
    kev_multiplier = compute_kev_multiplier(kev_listed)
    asset_weight = compute_asset_weight(asset_criticality)
    exposure_multiplier = compute_exposure_multiplier(exposure_context)
    zone_bonus = compute_zone_bonus(zone)

    raw_composite = (
        (base_score + exploit_score)
        * kev_multiplier
        * asset_weight
        * exposure_multiplier
        * zone_bonus
        * blast_radius
    )

    normalized = _normalize(raw_composite)

    return {
        "base_score": base_score,
        "exploit_score": exploit_score,
        "kev_multiplier": kev_multiplier,
        "asset_weight": asset_weight,
        "exposure_multiplier": exposure_multiplier,
        "zone_bonus": zone_bonus,
        "blast_radius": blast_radius,
        "raw_composite": raw_composite,
        "composite_score": normalized,
    }


def _normalize(raw_composite):
    max_theoretical = (100 + 100) * config.KEV_MULTIPLIER_LISTED * config.ASSET_WEIGHT["critical"] * config.EXPOSURE_MULTIPLIER["internet_facing"] * config.ZONE_WEIGHT_BONUS["internal"] * config.BLAST_RADIUS_MAX
    normalized = (raw_composite / max_theoretical) * config.COMPOSITE_SCORE_MAX
    if normalized > config.COMPOSITE_SCORE_MAX:
        return config.COMPOSITE_SCORE_MAX
    if normalized < config.COMPOSITE_SCORE_MIN:
        return config.COMPOSITE_SCORE_MIN
    return round(normalized, 2)


def compute_priority_tier(cvss_base, epss, kev_listed, asset_criticality, exposure_context):
    asset_criticality = (asset_criticality or "low").lower()
    exposure_context = (exposure_context or "restricted").lower()
    epss_high = epss >= config.EPSS_HIGH_THRESHOLD
    epss_medium = epss >= config.EPSS_MEDIUM_THRESHOLD
    cvss_high = cvss_base is not None and cvss_base >= config.CVSS_HIGH_THRESHOLD
    cvss_medium = cvss_base is not None and cvss_base >= config.CVSS_MEDIUM_THRESHOLD
    internet_facing = exposure_context == "internet_facing"
    critical_asset = asset_criticality == "critical"
    high_asset = asset_criticality == "high"

    if kev_listed:
        return "P1"
    if epss_high and internet_facing and critical_asset:
        return "P1"
    if epss_high and cvss_high:
        return "P2"
    if critical_asset and internet_facing:
        return "P2"
    if epss_medium and cvss_medium:
        return "P3"
    if high_asset:
        return "P3"
    return "P4"


def compute_criticality_mismatch(team2_criticality, computed_tier):
    tier_to_criticality_rank = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}
    criticality_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    computed_rank = tier_to_criticality_rank.get(computed_tier, 1)
    stated_rank = criticality_rank.get((team2_criticality or "low").lower(), 1)

    return computed_rank > stated_rank


def get_sla_hours(tier):
    return config.SLA_HOURS.get(tier, config.SLA_HOURS["P4"])
