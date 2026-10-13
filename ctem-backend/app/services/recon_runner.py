import asyncio
import json
import logging

logger = logging.getLogger("ctem.recon")
logging.basicConfig(level=logging.INFO)


async def run_recon(target, target_type):
    logger.info(f"[RECON] Starting reconnaissance for target={target} (type={target_type})")
    if target_type == "domain":
        return await _recon_domain(target)
    if target_type == "ip":
        return await _recon_ip(target)
    if target_type == "cidr":
        return await _recon_cidr(target)
    if target_type == "cloud_project":
        return await _recon_cloud_project(target)
    raise ValueError(f"unsupported target_type: {target_type}")


async def _recon_domain(domain):
    logger.info(f"[RECON] Discovering subdomains for {domain}...")
    subfinder_task = _run_subfinder(domain)
    crtsh_task = _run_crtsh(domain)
    subfinder_subs, crtsh_subs = await asyncio.gather(subfinder_task, crtsh_task, return_exceptions=True)

    subs1 = subfinder_subs if isinstance(subfinder_subs, list) else []
    subs2 = crtsh_subs if isinstance(crtsh_subs, list) else []
    subdomains = sorted(set(subs1 + subs2 + [domain]))
    logger.info(f"[RECON] Discovered {len(subdomains)} host(s): {subdomains[:5]}...")

    sem = asyncio.Semaphore(5)

    async def _scan_host(subdomain, idx, total):
        async with sem:
            logger.info(f"[RECON] [{idx}/{total}] Probing host {subdomain} (httpx, nmap, gau)...")
            probe = await _run_httpx(subdomain)
            ports = await _run_nmap(subdomain)
            leaks = await _run_gau(subdomain)
            logger.info(f"[RECON] [{idx}/{total}] Completed {subdomain}: {len(ports)} open port(s) found.")
            return {
                "hostname": subdomain,
                "root_domain": domain,
                "http_probe": probe,
                "open_ports": ports,
                "leak_indicators": leaks,
            }

    tasks = [_scan_host(sub, i + 1, len(subdomains)) for i, sub in enumerate(subdomains)]
    hosts = await asyncio.gather(*tasks)

    logger.info(f"[RECON] Finished reconnaissance for {domain}. Total hosts scanned: {len(hosts)}")
    return {"target": domain, "target_type": "domain", "hosts": list(hosts)}


async def _recon_ip(ip_address):
    logger.info(f"[RECON] Scanning IP {ip_address} with nmap...")
    ports = await _run_nmap(ip_address)
    logger.info(f"[RECON] Finished scanning IP {ip_address}: {len(ports)} open port(s)")
    return {"target": ip_address, "target_type": "ip", "hosts": [{"ip_address": ip_address, "open_ports": ports}]}


async def _recon_cidr(cidr):
    logger.info(f"[RECON] Scanning CIDR {cidr} with nmap...")
    ports = await _run_nmap(cidr)
    logger.info(f"[RECON] Finished scanning CIDR {cidr}: {len(ports)} open port(s)")
    return {"target": cidr, "target_type": "cidr", "hosts": [{"cidr": cidr, "open_ports": ports}]}


async def _recon_cloud_project(project_id):
    logger.info(f"[RECON] Querying GCP asset inventory for project {project_id}...")
    assets = await _run_gcp_asset_inventory(project_id)
    return {"target": project_id, "target_type": "cloud_project", "hosts": assets}


async def _run_subfinder(domain):
    try:
        return await _run_subprocess_json(["subfinder", "-d", domain, "-silent", "-oJ"], key="host")
    except Exception as e:
        logger.warning(f"[RECON] subfinder error for {domain}: {e}")
        return []


async def _run_crtsh(domain):
    import httpx
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return []
            data = response.json()
            names = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip()
                    if name.endswith(domain) and not name.startswith("*"):
                        names.add(name)
            return list(names)
    except Exception as e:
        logger.warning(f"[RECON] crt.sh lookup failed: {e}")
        return []


async def _run_httpx(hostname):
    try:
        return await _run_subprocess_json_single(["httpx", "-u", hostname, "-silent", "-json", "-tls-grab", "-status-code", "-title"])
    except Exception as e:
        logger.warning(f"[RECON] httpx error on {hostname}: {e}")
        return {}


async def _run_nmap(target):
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-sV", "-T4", "--top-ports", "100", "--host-timeout", "60s", "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=75.0)
        return _parse_nmap_xml(stdout.decode(errors="ignore"))
    except asyncio.TimeoutError:
        logger.warning(f"[RECON] nmap timed out for {target}")
        try:
            proc.kill()
        except Exception:
            pass
        return []
    except Exception as e:
        logger.warning(f"[RECON] nmap error for {target}: {e}")
        return []


def _parse_nmap_xml(xml_text):
    import xml.etree.ElementTree as ET
    ports = []
    try:
        root = ET.fromstring(xml_text)
        for port in root.iter("port"):
            state = port.find("state")
            service = port.find("service")
            if state is None or state.get("state") != "open":
                continue
            ports.append({
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None,
            })
    except Exception:
        pass
    return ports


async def _run_gau(hostname):
    try:
        proc = await asyncio.create_subprocess_exec(
            "gau", "--threads", "2", hostname,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        urls = [line.strip() for line in stdout.decode(errors="ignore").splitlines() if line.strip()]
        return urls[:50]
    except asyncio.TimeoutError:
        logger.warning(f"[RECON] gau timed out for {hostname}")
        try:
            proc.kill()
        except Exception:
            pass
        return []
    except Exception as e:
        logger.warning(f"[RECON] gau error for {hostname}: {e}")
        return []


async def _run_gcp_asset_inventory(project_id):
    try:
        proc = await asyncio.create_subprocess_exec(
            "gcloud", "asset", "search-all-resources", f"--scope=projects/{project_id}", "--format=json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45.0)
        return json.loads(stdout.decode(errors="ignore"))
    except Exception:
        return []


async def _run_subprocess_json(command, key):
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)
    results = []
    for line in stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            results.append(parsed.get(key, line))
        except Exception:
            results.append(line)
    return results


async def _run_subprocess_json_single(command):
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)
    output = stdout.decode(errors="ignore").strip()
    if not output:
        return {}
    try:
        return json.loads(output.splitlines()[0])
    except Exception:
        return {}
