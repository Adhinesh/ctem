import httpx
from app import config

_kev_cache = {"ids": None, "fetched_at": None}


KNOWN_CVSS_MAP = {
    "CVE-2011-2523": {"cvss_base": 9.8, "severity": "critical", "epss": 0.97, "kev": True},
    "CVE-2008-0166": {"cvss_base": 7.8, "severity": "high", "epss": 0.65, "kev": False},
    "CVE-2018-15473": {"cvss_base": 5.3, "severity": "medium", "epss": 0.35, "kev": False},
    "CVE-2008-0005": {"cvss_base": 7.5, "severity": "high", "epss": 0.32, "kev": False},
    "CVE-2021-41773": {"cvss_base": 9.8, "severity": "critical", "epss": 0.97, "kev": True},
    "CVE-2021-42013": {"cvss_base": 9.8, "severity": "critical", "epss": 0.95, "kev": True},
    "CVE-2017-15715": {"cvss_base": 7.0, "severity": "high", "epss": 0.25, "kev": False},
    "CVE-2007-2447": {"cvss_base": 9.8, "severity": "critical", "epss": 0.98, "kev": True},
    "CVE-2017-7494": {"cvss_base": 9.8, "severity": "critical", "epss": 0.88, "kev": True},
    "CVE-2009-0545": {"cvss_base": 7.5, "severity": "high", "epss": 0.42, "kev": False},
    "CVE-2015-3306": {"cvss_base": 9.8, "severity": "critical", "epss": 0.96, "kev": True},
    "CVE-2008-1447": {"cvss_base": 7.8, "severity": "high", "epss": 0.65, "kev": False},
    "CVE-2016-2776": {"cvss_base": 7.5, "severity": "high", "epss": 0.40, "kev": False},
    "CVE-2008-2079": {"cvss_base": 7.5, "severity": "high", "epss": 0.30, "kev": False},
    "CVE-2012-2122": {"cvss_base": 7.5, "severity": "high", "epss": 0.70, "kev": False},
    "CVE-2013-1899": {"cvss_base": 7.5, "severity": "high", "epss": 0.28, "kev": False},
    "CVE-2004-0911": {"cvss_base": 7.5, "severity": "high", "epss": 0.15, "kev": False},
    "CVE-2004-0175": {"cvss_base": 7.5, "severity": "high", "epss": 0.15, "kev": False},
    "CVE-2006-2369": {"cvss_base": 7.5, "severity": "high", "epss": 0.20, "kev": False},
    "CVE-2008-2936": {"cvss_base": 6.8, "severity": "medium", "epss": 0.12, "kev": False},
    "CVE-2017-7529": {"cvss_base": 7.5, "severity": "high", "epss": 0.45, "kev": False},
    "CVE-2019-11043": {"cvss_base": 9.8, "severity": "critical", "epss": 0.92, "kev": True},
    "CVE-2021-44228": {"cvss_base": 10.0, "severity": "critical", "epss": 0.97, "kev": True},
}


async def lookup_cvss(cve_id):
    # 1. Check curated fallback first for instant deterministic scoring
    if cve_id in KNOWN_CVSS_MAP:
        info = KNOWN_CVSS_MAP[cve_id]
        return {"cvss_base": info["cvss_base"], "severity": info["severity"], "source": "curated"}

    # 2. Check asset exposure / open port synthesized identifiers
    if cve_id.startswith("EXPOSURE-"):
        if "CRITICAL" in cve_id:
            return {"cvss_base": 9.2, "severity": "critical", "source": "asset_criticality"}
        if "HIGH" in cve_id:
            return {"cvss_base": 7.8, "severity": "high", "source": "asset_criticality"}
        if "MEDIUM" in cve_id:
            return {"cvss_base": 5.5, "severity": "medium", "source": "asset_criticality"}
        return {"cvss_base": 3.5, "severity": "low", "source": "asset_criticality"}

    if cve_id.startswith("CVE-PORT-"):
        return {"cvss_base": 5.0, "severity": "medium", "source": "open_port_baseline"}

    # 3. Try CIRCL with short timeout
    result = await _lookup_cvss_circl(cve_id)
    if result is not None:
        result["source"] = "circl"
        return result

    # 4. Try NVD with short timeout
    result = await _lookup_cvss_nvd(cve_id)
    if result is not None:
        result["source"] = "nvd"
        return result

    return {"cvss_base": 7.0, "severity": "high", "source": "default_estimate"}


async def _lookup_cvss_circl(cve_id):
    url = f"{config.CIRCL_BASE_URL}/cve/{cve_id}"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return None
            data = response.json()
            cvss_base = data.get("cvss")
            if cvss_base is None:
                return None
            return {"cvss_base": float(cvss_base), "severity": _severity_from_cvss(float(cvss_base))}
    except Exception:
        return None


async def _lookup_cvss_nvd(cve_id):
    headers = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY
    params = {"cveId": cve_id}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(config.NVD_BASE_URL, params=params, headers=headers)
            if response.status_code != 200:
                return None
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None
            cve_data = vulnerabilities[0]["cve"]
            metrics = cve_data.get("metrics", {})
            cvss_base = None
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    cvss_base = metrics[key][0]["cvssData"]["baseScore"]
                    break
            if cvss_base is None:
                return None
            return {"cvss_base": float(cvss_base), "severity": _severity_from_cvss(float(cvss_base))}
    except Exception:
        return None


def _severity_from_cvss(cvss_base):
    if cvss_base >= config.CVSS_HIGH_THRESHOLD:
        return "high"
    if cvss_base >= config.CVSS_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


async def lookup_epss(cve_id):
    if cve_id in KNOWN_CVSS_MAP:
        return KNOWN_CVSS_MAP[cve_id]["epss"]

    if cve_id.startswith("EXPOSURE-"):
        if "CRITICAL" in cve_id:
            return 0.88
        if "HIGH" in cve_id:
            return 0.65
        if "MEDIUM" in cve_id:
            return 0.35
        return 0.15

    if cve_id.startswith("CVE-PORT-"):
        return 0.20

    params = {"cve": cve_id}
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(config.EPSS_BASE_URL, params=params)
            if response.status_code == 200:
                data = response.json()
                rows = data.get("data", [])
                if rows:
                    return float(rows[0].get("epss", 0.0))
    except Exception:
        pass

    return 0.15


async def is_kev_listed(cve_id):
    if cve_id in KNOWN_CVSS_MAP and KNOWN_CVSS_MAP[cve_id]["kev"]:
        return True
    kev_ids = await _get_kev_ids()
    if kev_ids is None:
        return False
    return cve_id in kev_ids


async def _get_kev_ids():
    if _kev_cache["ids"] is not None:
        return _kev_cache["ids"]
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(config.KEV_FEED_URL)
            if response.status_code != 200:
                return None
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            ids = {item["cveID"] for item in vulnerabilities}
            _kev_cache["ids"] = ids
            return ids
    except Exception:
        return None
